import { createBuilder } from '@sgnl-ai/secevent';
import { transmitSET } from '@sgnl-ai/set-transmitter';
import { createPrivateKey } from 'crypto';

// Event type constant
const DEVICE_COMPLIANCE_CHANGE_EVENT = 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change';


/**
 * Parse subject JSON string
 */
function parseSubject(subjectStr) {
  try {
    return JSON.parse(subjectStr);
  } catch (error) {
    throw new Error(`Invalid subject JSON: ${error.message}`);
  }
}

/**
 * Parse reason JSON if it's i18n format, otherwise return as string
 */
function parseReason(reasonStr) {
  if (!reasonStr) return reasonStr;

  // Try to parse as JSON for i18n format
  try {
    const parsed = JSON.parse(reasonStr);
    // If it's an object, it's likely i18n format
    if (typeof parsed === 'object' && parsed !== null) {
      return parsed;
    }
  } catch {
    // Not JSON, treat as plain string
  }

  return reasonStr;
}

/**
 * Build destination URL
 */
function buildUrl(address, suffix) {
  if (!suffix) {
    return address;
  }
  const baseUrl = address.endsWith('/') ? address.slice(0, -1) : address;
  const cleanSuffix = suffix.startsWith('/') ? suffix.slice(1) : suffix;
  return `${baseUrl}/${cleanSuffix}`;
}

export default {
  /**
   * Transmit a CAEP Device Compliance Change event
   */
  invoke: async (params, context) => {
    // Validate required parameters
    if (!params.audience) {
      throw new Error('audience is required');
    }
    if (!params.subject) {
      throw new Error('subject is required');
    }
    if (!params.previousStatus) {
      throw new Error('previousStatus is required');
    }
    if (!params.currentStatus) {
      throw new Error('currentStatus is required');
    }
    if (!params.address) {
      throw new Error('address is required');
    }

    // Validate status values
    const validStatuses = ['compliant', 'not-compliant'];
    if (!validStatuses.includes(params.previousStatus)) {
      throw new Error(`previousStatus must be one of: ${validStatuses.join(', ')}`);
    }
    if (!validStatuses.includes(params.currentStatus)) {
      throw new Error(`currentStatus must be one of: ${validStatuses.join(', ')}`);
    }

    // Get secrets
    const ssfKey = context.secrets?.SSF_KEY;
    const ssfKeyId = context.secrets?.SSF_KEY_ID;
    const authToken = context.secrets?.AUTH_TOKEN;

    if (!ssfKey) {
      throw new Error('SSF_KEY secret is required');
    }
    if (!ssfKeyId) {
      throw new Error('SSF_KEY_ID secret is required');
    }

    // Parse parameters
    const issuer = params.issuer || 'https://sgnl.ai/';
    const signingMethod = params.signingMethod || 'RS256';
    const subject = parseSubject(params.subject);

    // Build event payload
    const eventPayload = {
      event_timestamp: params.eventTimestamp || Math.floor(Date.now() / 1000),
      previous_status: params.previousStatus,
      current_status: params.currentStatus
    };

    // Add optional event claims
    if (params.initiatingEntity) {
      eventPayload.initiating_entity = params.initiatingEntity;
    }
    if (params.reasonAdmin) {
      eventPayload.reason_admin = parseReason(params.reasonAdmin);
    }
    if (params.reasonUser) {
      eventPayload.reason_user = parseReason(params.reasonUser);
    }

    // Create the SET
    const builder = createBuilder();

    builder
      .withIssuer(issuer)
      .withAudience(params.audience)
      .withIat(Math.floor(Date.now() / 1000))
      .withClaim('sub_id', subject)  // CAEP 3.0 format
      .withEvent(DEVICE_COMPLIANCE_CHANGE_EVENT, eventPayload);

    // Sign the SET
    const privateKeyObject = createPrivateKey(ssfKey);
    const signingKey = {
      key: privateKeyObject,
      alg: signingMethod,
      kid: ssfKeyId
    };

    const { jwt } = await builder.sign(signingKey);

    // Build destination URL
    const url = buildUrl(params.address, params.addressSuffix);

    // Transmit the SET using the library
    return await transmitSET(jwt, url, {
      authToken,
      headers: {
        'User-Agent': params.userAgent || 'SGNL-Action-Framework/1.0'
      }
    });
  },

  /**
   * Error handler for retryable failures
   */
  error: async (params, _context) => {
    const { error } = params;

    // Check if this is a retryable error
    if (error.message?.includes('429') ||
        error.message?.includes('502') ||
        error.message?.includes('503') ||
        error.message?.includes('504')) {
      return { status: 'retry_requested' };
    }

    // Non-retryable error
    throw error;
  },

  /**
   * Cleanup handler
   */
  halt: async (_params, _context) => {
    return { status: 'halted' };
  }
};