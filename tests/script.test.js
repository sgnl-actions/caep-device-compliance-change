import { jest } from '@jest/globals';

// Mock the @sgnl-ai/secevent module
jest.unstable_mockModule('@sgnl-ai/secevent', () => {
  const mockBuilder = {
    withIssuer: jest.fn().mockReturnThis(),
    withAudience: jest.fn().mockReturnThis(),
    withIat: jest.fn().mockReturnThis(),
    withClaim: jest.fn().mockReturnThis(),
    withEvent: jest.fn().mockReturnThis(),
    sign: jest.fn().mockResolvedValue({ jwt: 'mock.jwt.token' })
  };
  return {
    createBuilder: jest.fn(() => mockBuilder)
  };
});

// Mock crypto module
jest.unstable_mockModule('crypto', () => ({
  createPrivateKey: jest.fn(() => 'mock-private-key')
}));

// Import after mocking
const { createBuilder } = await import('@sgnl-ai/secevent');
await import('crypto');
const script = (await import('../src/script.mjs')).default;

// Mock fetch globally
global.fetch = jest.fn();

describe('CAEP Device Compliance Change Transmitter', () => {
  let mockBuilder;
  const mockContext = {
    secrets: {
      SSF_KEY: '-----BEGIN RSA PRIVATE KEY-----\nMOCK_KEY\n-----END RSA PRIVATE KEY-----',
      SSF_KEY_ID: 'test-key-id',
      AUTH_TOKEN: 'Bearer test-token'
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockBuilder = createBuilder();
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: jest.fn().mockResolvedValue('{"success":true}')
    });
  });

  describe('invoke', () => {
    const validParams = {
      audience: 'https://example.com',
      subject: '{"format":"account","uri":"acct:user@service.example.com"}',
      previousStatus: 'compliant',
      currentStatus: 'not-compliant',
      address: 'https://receiver.example.com/events'
    };

    test('should successfully transmit a device compliance change event', async () => {
      const result = await script.invoke(validParams, mockContext);

      expect(result).toEqual({
        status: 'success',
        statusCode: 200,
        body: '{"success":true}',
        retryable: false
      });

      expect(createBuilder).toHaveBeenCalled();
      expect(mockBuilder.withIssuer).toHaveBeenCalledWith('https://sgnl.ai/');
      expect(mockBuilder.withAudience).toHaveBeenCalledWith('https://example.com');
      expect(mockBuilder.withClaim).toHaveBeenCalledWith('sub_id', {
        format: 'account',
        uri: 'acct:user@service.example.com'
      });
      expect(mockBuilder.withEvent).toHaveBeenCalledWith(
        'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
        expect.objectContaining({
          event_timestamp: expect.any(Number),
          previous_status: 'compliant',
          current_status: 'not-compliant'
        })
      );
    });

    test('should include optional event claims when provided', async () => {
      const params = {
        ...validParams,
        initiatingEntity: 'policy',
        reasonAdmin: 'Landspeed Policy Violation: C076E82F',
        reasonUser: 'Access attempt from multiple regions',
        eventTimestamp: 1234567890
      };

      await script.invoke(params, mockContext);

      expect(mockBuilder.withEvent).toHaveBeenCalledWith(
        'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
        expect.objectContaining({
          event_timestamp: 1234567890,
          previous_status: 'compliant',
          current_status: 'not-compliant',
          initiating_entity: 'policy',
          reason_admin: 'Landspeed Policy Violation: C076E82F',
          reason_user: 'Access attempt from multiple regions'
        })
      );
    });

    test('should parse i18n JSON reasons', async () => {
      const params = {
        ...validParams,
        reasonAdmin: '{"en": "Policy violation", "de": "Richtlinienverstoss"}',
        reasonUser: '{"en": "Access denied", "de": "Zugriff verweigert"}'
      };

      await script.invoke(params, mockContext);

      expect(mockBuilder.withEvent).toHaveBeenCalledWith(
        'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
        expect.objectContaining({
          reason_admin: { en: 'Policy violation', de: 'Richtlinienverstoss' },
          reason_user: { en: 'Access denied', de: 'Zugriff verweigert' }
        })
      );
    });

    test('should validate status transitions', async () => {
      const params = {
        ...validParams,
        previousStatus: 'not-compliant',
        currentStatus: 'compliant'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(mockBuilder.withEvent).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          previous_status: 'not-compliant',
          current_status: 'compliant'
        })
      );
    });

    test('should throw error for invalid previousStatus', async () => {
      const params = {
        ...validParams,
        previousStatus: 'invalid-status'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('previousStatus must be one of: compliant, not-compliant');
    });

    test('should throw error for invalid currentStatus', async () => {
      const params = {
        ...validParams,
        currentStatus: 'invalid-status'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('currentStatus must be one of: compliant, not-compliant');
    });

    test('should throw error for missing audience', async () => {
      const params = { ...validParams };
      delete params.audience;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('audience is required');
    });

    test('should throw error for missing subject', async () => {
      const params = { ...validParams };
      delete params.subject;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('subject is required');
    });

    test('should throw error for missing previousStatus', async () => {
      const params = { ...validParams };
      delete params.previousStatus;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('previousStatus is required');
    });

    test('should throw error for missing currentStatus', async () => {
      const params = { ...validParams };
      delete params.currentStatus;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('currentStatus is required');
    });

    test('should throw error for missing address', async () => {
      const params = { ...validParams };
      delete params.address;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('address is required');
    });

    test('should throw error for invalid subject JSON', async () => {
      const params = {
        ...validParams,
        subject: 'invalid json'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('Invalid subject JSON');
    });

    test('should throw error for missing SSF_KEY secret', async () => {
      const context = {
        secrets: {
          SSF_KEY_ID: 'test-key-id'
        }
      };

      await expect(script.invoke(validParams, context))
        .rejects.toThrow('SSF_KEY secret is required');
    });

    test('should throw error for missing SSF_KEY_ID secret', async () => {
      const context = {
        secrets: {
          SSF_KEY: 'mock-key'
        }
      };

      await expect(script.invoke(validParams, context))
        .rejects.toThrow('SSF_KEY_ID secret is required');
    });

    test('should handle non-retryable HTTP errors', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: jest.fn().mockResolvedValue('{"error":"Invalid request"}')
      });

      const result = await script.invoke(validParams, mockContext);

      expect(result).toEqual({
        status: 'failed',
        statusCode: 400,
        body: '{"error":"Invalid request"}',
        retryable: false
      });
    });

    test('should throw error for retryable HTTP errors', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        text: jest.fn().mockResolvedValue('Rate limited')
      });

      await expect(script.invoke(validParams, mockContext))
        .rejects.toThrow('SET transmission failed: 429 Too Many Requests');
    });

    test('should use custom issuer and signing method', async () => {
      const params = {
        ...validParams,
        issuer: 'https://custom.issuer.com',
        signingMethod: 'RS512'
      };

      await script.invoke(params, mockContext);

      expect(mockBuilder.withIssuer).toHaveBeenCalledWith('https://custom.issuer.com');
      expect(mockBuilder.sign).toHaveBeenCalledWith({
        key: 'mock-private-key',
        alg: 'RS512',
        kid: 'test-key-id'
      });
    });

    test('should append address suffix when provided', async () => {
      const params = {
        ...validParams,
        addressSuffix: '/v1/events'
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://receiver.example.com/events/v1/events',
        expect.any(Object)
      );
    });

    test('should use custom user agent when provided', async () => {
      const params = {
        ...validParams,
        userAgent: 'CustomAgent/1.0'
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'User-Agent': 'CustomAgent/1.0'
          })
        })
      );
    });

    test('should send correct content type header', async () => {
      await script.invoke(validParams, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/secevent+jwt',
            'Accept': 'application/json'
          }),
          body: 'mock.jwt.token'
        })
      );
    });
  });

  describe('error handler', () => {
    test('should request retry for 429 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 429 Too Many Requests')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 502 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 502 Bad Gateway')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 503 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 503 Service Unavailable')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should request retry for 504 errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 504 Gateway Timeout')
      };

      const result = await script.error(params, {});

      expect(result).toEqual({ status: 'retry_requested' });
    });

    test('should re-throw non-retryable errors', async () => {
      const params = {
        error: new Error('Authentication failed: 401 Unauthorized')
      };

      await expect(script.error(params, {}))
        .rejects.toThrow('Authentication failed: 401 Unauthorized');
    });
  });

  describe('halt handler', () => {
    test('should return halted status', async () => {
      const result = await script.halt({}, {});

      expect(result).toEqual({ status: 'halted' });
    });
  });
});