import { once } from 'node:events';
import { TextDecoder } from 'node:util';
import { McpToolInputError } from './mcp-config.mjs';
import {
  LEGACY_MCP_VERSIONS,
  MCP_SERVER_VERSION,
  MODERN_MCP_VERSION,
  SUPPORTED_MCP_VERSIONS,
  callMcpTool,
  listMcpTools,
} from './mcp-tools.mjs';

const SERVER_INFO = Object.freeze({ name: 'sprintloop-assurance-kit', version: MCP_SERVER_VERSION });
const SERVER_INSTRUCTIONS = 'Read-only offline Assurance inspection. MCP results are advisory and never authorize, approve, merge, deploy, mutate policy/trust, or enable enforcement. Current verification requires an explicit external candidate and complete receiver context; never substitute dossier or candidate-controlled values.';
const JSON_RPC = '2.0';
const ERROR = Object.freeze({
  PARSE: -32_700,
  INVALID_REQUEST: -32_600,
  METHOD_NOT_FOUND: -32_601,
  INVALID_PARAMS: -32_602,
  INTERNAL: -32_603,
  NOT_INITIALIZED: -32_002,
  UNSUPPORTED_PROTOCOL: -32_022,
});

export class AssuranceMcpServer {
  constructor(config, { errorOutput } = {}) {
    this.config = config;
    this.errorOutput = errorOutput;
    this.legacyState = 'none';
    this.legacyVersion = null;
    this.toolCalls = 0;
  }

  async dispatch(message) {
    const notification = isObject(message) && !Object.hasOwn(message, 'id');
    try {
      validateRpcMessage(message);
    } catch (error) {
      // JSON-RPC notifications never receive a response, including malformed
      // notification-shaped objects. Parse errors remain request-independent.
      if (notification) return null;
      throw error;
    }
    if (notification) {
      this.handleNotification(message);
      return null;
    }
    try {
      const era = this.requestEra(message);
      const result = await this.handleRequest(message, era);
      return { jsonrpc: JSON_RPC, id: message.id, result: era === 'modern' ? modernResult(result) : result };
    } catch (error) {
      if (error instanceof RpcFault) return errorResponse(message.id, error.code, error.message, error.data);
      this.logInternal();
      return errorResponse(message.id, ERROR.INTERNAL, 'Internal Assurance MCP error.');
    }
  }

  requestEra(message) {
    if (message.method === 'server/discover') {
      validateModernMetadata(message.params);
      return 'modern';
    }
    if (message.method === 'initialize') return 'legacy';
    const version = message.params?._meta?.['io.modelcontextprotocol/protocolVersion'];
    if (version !== undefined) {
      validateModernMetadata(message.params);
      return 'modern';
    }
    if (this.legacyState === 'ready') return 'legacy';
    throw new RpcFault(ERROR.NOT_INITIALIZED, 'Legacy MCP client must initialize before invoking methods.');
  }

  async handleRequest(message, era) {
    if (message.method === 'server/discover') return discoverResult();
    if (message.method === 'initialize') return this.initialize(message.params);
    if (message.method === 'ping') {
      if (era === 'modern') throw new RpcFault(ERROR.METHOD_NOT_FOUND, 'Method not found.');
      validateLegacyEmptyParams(message.params);
      return {};
    }
    if (message.method === 'tools/list') {
      validateListParams(message.params, era);
      const result = { tools: listMcpTools() };
      if (era === 'modern') Object.assign(result, { ttlMs: 3_600_000, cacheScope: 'public' });
      return result;
    }
    if (message.method === 'tools/call') return this.callTool(message.params, era);
    throw new RpcFault(ERROR.METHOD_NOT_FOUND, 'Method not found.');
  }

  initialize(params) {
    if (this.legacyState !== 'none') throw new RpcFault(ERROR.INVALID_REQUEST, 'MCP legacy initialization may occur only once.');
    validateInitializeParams(params);
    const requested = params.protocolVersion;
    const selected = LEGACY_MCP_VERSIONS.includes(requested) ? requested : LEGACY_MCP_VERSIONS[0];
    this.legacyState = 'waiting-for-initialized';
    this.legacyVersion = selected;
    return {
      protocolVersion: selected,
      capabilities: { tools: { listChanged: false } },
      serverInfo: SERVER_INFO,
      instructions: SERVER_INSTRUCTIONS,
    };
  }

  handleNotification(message) {
    if (message.jsonrpc !== JSON_RPC || typeof message.method !== 'string') return;
    if (message.method === 'notifications/initialized' && this.legacyState === 'waiting-for-initialized') {
      this.legacyState = 'ready';
    }
    // The server has no server-initiated requests or long-running work. Cancellation
    // and unknown notifications therefore require no response or mutable state.
  }

  async callTool(params, era) {
    validateCallParams(params, era);
    if (!listMcpTools().some((tool) => tool.name === params.name)) {
      throw new RpcFault(ERROR.INVALID_PARAMS, 'Unknown tool.');
    }
    this.toolCalls += 1;
    if (this.toolCalls > this.config.limits.maxToolCalls) {
      return toolError('TOOL_CALL_LIMIT', 'Configured MCP tool-call limit has been reached.');
    }
    try {
      const structured = await callMcpTool(params.name, params.arguments ?? {}, this.config);
      return {
        content: [{ type: 'text', text: JSON.stringify(structured) }],
        structuredContent: structured,
        isError: false,
      };
    } catch (error) {
      if (error instanceof McpToolInputError) return toolError(error.code, error.message);
      this.logInternal();
      return toolError('TOOL_EXECUTION_FAILED', 'Assurance tool could not complete safely.');
    }
  }

  logInternal() {
    this.errorOutput?.write?.('SprintLoop Assurance MCP: internal operation failed; no host path or input content was emitted.\n');
  }
}

export async function runMcpStdioServer({ config, input, output, errorOutput }) {
  if (!config || !input || !output) throw new TypeError('MCP stdio server requires config, input, and output streams');
  const server = new AssuranceMcpServer(config, { errorOutput });
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const framer = createLineFramer(config.limits.maxMessageBytes);

  for await (const rawChunk of input) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
    for (const frame of framer.push(chunk)) {
      if (frame.tooLarge) {
        await writeRpc(output, errorResponse(null, ERROR.PARSE, 'JSON-RPC message exceeds configured byte limit.'), config.limits.maxMessageBytes);
        continue;
      }
      await processFrame(frame.bytes, decoder, server, output, config.limits.maxMessageBytes);
    }
  }
  const tail = framer.finish();
  if (tail) {
    const message = tail.tooLarge ? 'JSON-RPC message exceeds configured byte limit.' : 'Truncated JSON-RPC message at end of input.';
    await writeRpc(output, errorResponse(null, ERROR.PARSE, message), config.limits.maxMessageBytes);
  }
}

async function processFrame(bytes, decoder, server, output, maxBytes) {
  let message;
  try {
    if (bytes.length === 0) throw new SyntaxError('empty frame');
    message = JSON.parse(decoder.decode(bytes));
  } catch {
    await writeRpc(output, errorResponse(null, ERROR.PARSE, 'Invalid JSON-RPC message.'), maxBytes);
    return;
  }
  let response;
  try {
    response = await server.dispatch(message);
  } catch (error) {
    if (error instanceof RpcFault) response = errorResponse(validId(message?.id) ? message.id : null, error.code, error.message, error.data);
    else response = errorResponse(validId(message?.id) ? message.id : null, ERROR.INTERNAL, 'Internal Assurance MCP error.');
  }
  if (response) await writeRpc(output, response, maxBytes);
}

async function writeRpc(output, response, maxBytes) {
  let bytes = Buffer.from(`${JSON.stringify(response)}\n`, 'utf8');
  if (bytes.length > maxBytes) {
    // Never reflect a request-controlled identifier into the bounded fallback.
    // The terminating LF is part of the protocol frame and therefore part of
    // the configured byte limit.
    bytes = Buffer.from(`${JSON.stringify(errorResponse(null, ERROR.INTERNAL, 'MCP response exceeds configured byte limit.'))}\n`, 'utf8');
  }
  if (bytes.length > maxBytes) throw new Error('Configured MCP message limit cannot carry a bounded error response.');
  if (!output.write(bytes)) await once(output, 'drain');
}

function createLineFramer(maxBytes) {
  let parts = [];
  let length = 0;
  let discarding = false;
  return {
    push(chunk) {
      const frames = [];
      let start = 0;
      for (let index = 0; index < chunk.length; index += 1) {
        if (chunk[index] !== 0x0a) continue;
        const segment = chunk.subarray(start, index);
        if (!discarding) append(segment);
        if (discarding) frames.push({ tooLarge: true });
        else frames.push({ bytes: complete() });
        parts = [];
        length = 0;
        discarding = false;
        start = index + 1;
      }
      if (start < chunk.length && !discarding) append(chunk.subarray(start));
      return frames;

      function append(segment) {
        if (length + segment.length > maxBytes) {
          parts = [];
          length = 0;
          discarding = true;
          return;
        }
        if (segment.length) parts.push(segment);
        length += segment.length;
      }

      function complete() {
        let bytes = Buffer.concat(parts, length);
        if (bytes.at(-1) === 0x0d) bytes = bytes.subarray(0, -1);
        return bytes;
      }
    },
    finish() {
      if (discarding) return { tooLarge: true };
      if (length > 0) return { tooLarge: false };
      return null;
    },
  };
}

function validateRpcMessage(message) {
  if (!isObject(message) || message.jsonrpc !== JSON_RPC || typeof message.method !== 'string' || message.method.length === 0) {
    throw new RpcFault(ERROR.INVALID_REQUEST, 'Invalid JSON-RPC request.');
  }
  if (Object.hasOwn(message, 'id') && !validId(message.id)) throw new RpcFault(ERROR.INVALID_REQUEST, 'Invalid JSON-RPC request ID.');
  const allowed = new Set(['jsonrpc', 'id', 'method', 'params']);
  if (Object.keys(message).some((key) => !allowed.has(key))) throw new RpcFault(ERROR.INVALID_REQUEST, 'Unexpected JSON-RPC request member.');
  if (message.params !== undefined && !isObject(message.params)) throw new RpcFault(ERROR.INVALID_PARAMS, 'MCP params must be an object.');
}

function validateModernMetadata(params) {
  if (!isObject(params) || !isObject(params._meta)) throw new RpcFault(ERROR.INVALID_PARAMS, 'Modern MCP request metadata is required.');
  const version = params._meta['io.modelcontextprotocol/protocolVersion'];
  if (version !== MODERN_MCP_VERSION) {
    throw new RpcFault(ERROR.UNSUPPORTED_PROTOCOL, 'Unsupported MCP protocol version.', {
      supported: [...SUPPORTED_MCP_VERSIONS],
      requested: typeof version === 'string' ? version : '(missing)',
    });
  }
  if (!isObject(params._meta['io.modelcontextprotocol/clientCapabilities'])) {
    throw new RpcFault(ERROR.INVALID_PARAMS, 'Modern MCP client capabilities are required per request.');
  }
  const client = params._meta['io.modelcontextprotocol/clientInfo'];
  if (client !== undefined && (!isObject(client) || !boundedString(client.name, 1, 128) || !boundedString(client.version, 1, 128))) {
    throw new RpcFault(ERROR.INVALID_PARAMS, 'Modern MCP clientInfo is malformed.');
  }
}

function validateInitializeParams(params) {
  if (!isObject(params)) throw new RpcFault(ERROR.INVALID_PARAMS, 'Initialize params are required.');
  const allowed = new Set(['protocolVersion', 'capabilities', 'clientInfo', '_meta']);
  if (Object.keys(params).some((key) => !allowed.has(key))) throw new RpcFault(ERROR.INVALID_PARAMS, 'Initialize params contain an unexpected member.');
  if (!boundedString(params.protocolVersion, 1, 64) || !isObject(params.capabilities) || !isObject(params.clientInfo)
    || !boundedString(params.clientInfo.name, 1, 128) || !boundedString(params.clientInfo.version, 1, 128)) {
    throw new RpcFault(ERROR.INVALID_PARAMS, 'Initialize params are malformed.');
  }
}

function validateListParams(params, era) {
  if (params === undefined && era === 'legacy') return;
  if (!isObject(params)) throw new RpcFault(ERROR.INVALID_PARAMS, 'tools/list params must be an object.');
  const allowed = era === 'modern' ? new Set(['_meta', 'cursor']) : new Set(['_meta', 'cursor']);
  if (Object.keys(params).some((key) => !allowed.has(key))) throw new RpcFault(ERROR.INVALID_PARAMS, 'tools/list params contain an unexpected member.');
  if (params.cursor !== undefined) throw new RpcFault(ERROR.INVALID_PARAMS, 'This fixed tool catalog has no pagination cursor.');
}

function validateCallParams(params, era) {
  if (!isObject(params) || !boundedString(params.name, 1, 128)) throw new RpcFault(ERROR.INVALID_PARAMS, 'tools/call params are malformed.');
  const allowed = era === 'modern'
    ? new Set(['_meta', 'name', 'arguments', 'inputResponses', 'requestState'])
    : new Set(['_meta', 'name', 'arguments']);
  if (Object.keys(params).some((key) => !allowed.has(key))) throw new RpcFault(ERROR.INVALID_PARAMS, 'tools/call params contain an unexpected member.');
  if (params.arguments !== undefined && !isObject(params.arguments)) throw new RpcFault(ERROR.INVALID_PARAMS, 'Tool arguments must be an object.');
  if (params.inputResponses !== undefined || params.requestState !== undefined) {
    throw new RpcFault(ERROR.INVALID_PARAMS, 'Assurance read-only tools do not use multi-round-trip input.');
  }
}

function validateLegacyEmptyParams(params) {
  if (params === undefined) return;
  if (!isObject(params) || Object.keys(params).some((key) => key !== '_meta')) throw new RpcFault(ERROR.INVALID_PARAMS, 'ping params must be empty.');
}

function discoverResult() {
  return {
    supportedVersions: [...SUPPORTED_MCP_VERSIONS],
    capabilities: { tools: { listChanged: false } },
    instructions: SERVER_INSTRUCTIONS,
    ttlMs: 3_600_000,
    cacheScope: 'public',
  };
}

function modernResult(result) {
  return {
    resultType: 'complete',
    ...result,
    _meta: {
      ...(result?._meta ?? {}),
      'io.modelcontextprotocol/serverInfo': SERVER_INFO,
    },
  };
}

function toolError(code, message) {
  return {
    content: [{ type: 'text', text: JSON.stringify({ error: { code, message } }) }],
    isError: true,
  };
}

function errorResponse(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: JSON_RPC, id, error };
}

function validId(value) {
  return (typeof value === 'string'
      && Buffer.byteLength(value, 'utf8') <= 256
      && !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(value))
    || (typeof value === 'number' && Number.isSafeInteger(value));
}

function boundedString(value, minimum, maximum) {
  return typeof value === 'string' && value.length >= minimum && value.length <= maximum;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

class RpcFault extends Error {
  constructor(code, message, data) {
    super(message);
    this.code = code;
    this.data = data;
  }
}
