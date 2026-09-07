import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  DEFAULTS,
  identityEndpoints,
  issuerFor,
  legacyDeviceFlowRequested,
  legacyEndpoints,
  resolveConfig,
} from '../src/config.js';

const CONTRACT_SCOPES = [
  'openid',
  'profile',
  'offline_access',
  'research:read',
  'research:write',
  'findings:read',
  'findings:write',
  'campaigns:read',
  'campaigns:write',
  'operations:read',
  'operations:write',
];

describe('resolveConfig', () => {
  it('defaults to the loopback client registered in the contract', () => {
    const config = resolveConfig({});
    assert.equal(config.mode, 'loopback');
    assert.deepEqual(config, {
      mode: 'loopback',
      issuer: 'https://id.dev.know.sh',
      clientId: 'know-cli-development',
      resource: 'https://mcp.dev.know.sh/',
      scopes: DEFAULTS.scopes,
      mcpUrl: 'https://mcp.dev.know.sh/mcp',
    });
  });

  it('requests the three identity scopes plus the eight MCP scopes, and never email', () => {
    assert.deepEqual(DEFAULTS.scopes.split(' '), CONTRACT_SCOPES);
    assert.ok(!DEFAULTS.scopes.split(' ').includes('email'));
  });

  it('keeps the MCP resource identifier trailing slash', () => {
    assert.equal(DEFAULTS.resource, 'https://mcp.dev.know.sh/');
  });

  it('applies environment overrides', () => {
    const config = resolveConfig({
      KNOWSH_ISSUER: 'https://id.know.sh',
      KNOWSH_CLIENT_ID: 'know-cli-production',
      KNOWSH_RESOURCE: 'https://mcp.know.sh/',
      KNOWSH_SCOPES: 'openid',
      KNOWSH_MCP_URL: 'https://mcp.know.sh/mcp',
    });
    assert.deepEqual(config, {
      mode: 'loopback',
      issuer: 'https://id.know.sh',
      clientId: 'know-cli-production',
      resource: 'https://mcp.know.sh/',
      scopes: 'openid',
      mcpUrl: 'https://mcp.know.sh/mcp',
    });
  });

  it('falls back to the Auth0 device flow only behind the legacy flag', () => {
    assert.equal(legacyDeviceFlowRequested({}), false);
    assert.equal(legacyDeviceFlowRequested({ KNOWSH_LEGACY_DEVICE_FLOW: '0' }), false);
    assert.equal(legacyDeviceFlowRequested({ KNOWSH_LEGACY_DEVICE_FLOW: '1' }), true);
    assert.equal(legacyDeviceFlowRequested({ KNOWSH_LEGACY_DEVICE_FLOW: 'TRUE' }), true);

    const config = resolveConfig({ KNOWSH_LEGACY_DEVICE_FLOW: '1' });
    assert.equal(config.mode, 'device');
    assert.equal(config.mode === 'device' && config.auth0Domain, 'dev-hcpmhp1w4f2455pb.us.auth0.com');
    assert.equal(config.mode === 'device' && config.auth0ClientId, 'rEsn27jbd8IAD7k1JkRsES3pEKFwyjJd');
    assert.equal(config.mode === 'device' && config.audience, 'https://mcp.know.sh');
    assert.ok(config.scopes.split(' ').includes('email'));
  });
});

describe('endpoints', () => {
  it('derives the identity host endpoints from the issuer', () => {
    assert.deepEqual(identityEndpoints('https://id.dev.know.sh/'), {
      authorize: 'https://id.dev.know.sh/connect/authorize',
      token: 'https://id.dev.know.sh/connect/token',
      revocation: 'https://id.dev.know.sh/connect/revocation',
    });
  });

  it('derives the legacy Auth0 endpoints from the domain', () => {
    assert.deepEqual(legacyEndpoints('https://tenant.us.auth0.com/'), {
      deviceCode: 'https://tenant.us.auth0.com/oauth/device/code',
      token: 'https://tenant.us.auth0.com/oauth/token',
    });
  });

  it('reports the issuer each mode stamps on a token set', () => {
    assert.equal(issuerFor(resolveConfig({})), 'https://id.dev.know.sh');
    assert.equal(
      issuerFor(resolveConfig({ KNOWSH_LEGACY_DEVICE_FLOW: '1' })),
      'https://dev-hcpmhp1w4f2455pb.us.auth0.com/',
    );
  });
});
