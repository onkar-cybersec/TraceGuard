/**
 * Synthetic security event datasets for demo and benchmarking.
 * Strict zero real-credential / zero PII policy. Uses RFC documentation and reserved IPs.
 */

export const TRIGGER_DEMO_JSON = JSON.stringify(
  {
    events: [
      // Benign baseline event 1
      {
        event_type: 'api_request',
        timestamp: '2026-10-07T08:00:00Z',
        user: 'service_runner',
        source_ip: '10.0.1.15',
        destination_ip: '10.0.2.20',
        destination_port: 443,
        status: 'success',
        bytes: 1204,
        message: 'Routine health check ping to microservice mesh',
      },
      // Benign baseline event 2 (large internal transfer - should NOT trigger TG004 because it is RFC 1918)
      {
        event_type: 'database_backup_sync',
        timestamp: '2026-10-07T08:05:00Z',
        user: 'db_admin_sync',
        source_ip: '10.10.4.100',
        destination_ip: '192.168.50.25',
        destination_port: 5432,
        status: 'success',
        bytes: 45000000, // 45 MB internal
        message: 'Nightly database snapshot replication to internal cold storage',
      },
      // Benign baseline event 3 (IPv6 ULA internal transfer - should NOT trigger TG004)
      {
        event_type: 'file_transfer',
        timestamp: '2026-10-07T08:08:00Z',
        user: 'app_sync',
        source_ip: 'fd00:abcd::1',
        destination_ip: 'fd00:abcd::99',
        destination_port: 8443,
        status: 'success',
        bytes: 25000000,
        message: 'Internal cluster container image distribution',
      },

      // --- TG001: 5+ failed auth events for j.miller from 198.51.100.45 in 5m ---
      {
        event_type: 'user_login',
        timestamp: '2026-10-07T08:15:10Z',
        user: 'j.miller',
        source_ip: '198.51.100.45',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'Failed password verification for console login',
      },
      {
        event_type: 'user_login',
        timestamp: '2026-10-07T08:15:45Z',
        user: 'j.miller',
        source_ip: '198.51.100.45',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'Invalid credential provided',
      },
      {
        event_type: 'user_login',
        timestamp: '2026-10-07T08:16:30Z',
        user: 'j.miller',
        source_ip: '198.51.100.45',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'Failed login retry attempt 3',
      },
      {
        event_type: 'user_login',
        timestamp: '2026-10-07T08:17:15Z',
        user: 'j.miller',
        source_ip: '198.51.100.45',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'Authentication error - incorrect passcode',
      },
      {
        event_type: 'user_login',
        timestamp: '2026-10-07T08:18:02Z',
        user: 'j.miller',
        source_ip: '198.51.100.45',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'Fifth consecutive failed login from host',
      },

      // Unrelated user benign login during same window (proving isolation)
      {
        event_type: 'user_login',
        timestamp: '2026-10-07T08:17:30Z',
        user: 'sarah.kim',
        source_ip: '203.0.113.12',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'success',
        message: 'Successful single-sign-on authentication',
      },

      // --- TG002: 5+ failed auth events for alex.chen followed by success within 10m ---
      {
        event_type: 'sso_auth',
        timestamp: '2026-10-07T08:30:00Z',
        user: 'alex.chen',
        source_ip: '203.0.113.88',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'SSO attempt failed - bad credentials',
      },
      {
        event_type: 'sso_auth',
        timestamp: '2026-10-07T08:30:40Z',
        user: 'alex.chen',
        source_ip: '203.0.113.88',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'SSO attempt failed - token rejected',
      },
      {
        event_type: 'sso_auth',
        timestamp: '2026-10-07T08:31:20Z',
        user: 'alex.chen',
        source_ip: '203.0.113.88',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'SSO attempt failed - bad password hash',
      },
      {
        event_type: 'sso_auth',
        timestamp: '2026-10-07T08:32:05Z',
        user: 'alex.chen',
        source_ip: '203.0.113.88',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'SSO attempt failed - invalid token',
      },
      {
        event_type: 'sso_auth',
        timestamp: '2026-10-07T08:32:50Z',
        user: 'alex.chen',
        source_ip: '203.0.113.88',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'failure',
        message: 'SSO attempt failed - lockout imminent',
      },
      {
        event_type: 'sso_auth',
        timestamp: '2026-10-07T08:35:10Z', // 5m10s after first failure, within 10m window
        user: 'alex.chen',
        source_ip: '203.0.113.88',
        destination_ip: '192.0.2.1',
        destination_port: 443,
        status: 'success',
        message: 'Session token issued after valid authorization response',
      },

      // --- TG003: Administrative role assignment ---
      {
        event_type: 'iam_role_change',
        timestamp: '2026-10-07T08:42:00Z',
        user: 'm.rodriguez',
        source_ip: '10.0.1.44',
        new_role: 'administrator',
        status: 'success',
        message: 'User m.rodriguez promoted to tenant administrator for cluster operations',
      },
      // Benign non-privileged role change (should NOT trigger TG003)
      {
        event_type: 'iam_role_change',
        timestamp: '2026-10-07T08:44:00Z',
        user: 't.taylor',
        source_ip: '10.0.1.44',
        new_role: 'billing_viewer',
        status: 'success',
        message: 'User assigned read-only invoices review role',
      },

      // --- TG004: Suspicious outbound transfer >= 10 MiB to public IP & port 4444 ---
      {
        event_type: 'network_egress',
        timestamp: '2026-10-07T08:50:00Z',
        user: 'backup_daemon',
        source_ip: '10.0.5.80',
        destination_ip: '93.184.216.34', // Public IP
        destination_port: 443,
        bytes: 18454912, // ~17.6 MiB
        status: 'success',
        message: 'High-volume outbound data flow to external destination endpoint',
      },
      {
        event_type: 'network_connection',
        timestamp: '2026-10-07T08:52:15Z',
        user: 'workstation_04',
        source_ip: '10.0.5.82',
        destination_ip: '142.250.190.46',
        destination_port: 4444, // Suspicious Metasploit port
        bytes: 4096,
        status: 'established',
        message: 'Outbound TCP socket established on non-standard port 4444',
      },

      // --- TG005: Sensitive Secret Leak in event fields (fake test values) ---
      {
        event_type: 'app_debug_log',
        timestamp: '2026-10-07T08:58:00Z',
        user: 'ci_pipeline_bot',
        source_ip: '10.0.1.99',
        destination_ip: '10.0.1.5',
        destination_port: 8080,
        status: 'info',
        message: 'Deploy task initialized with AWS key AKIAIOSFODNN7EXAMPLE and header Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.synthetic_signature_token',
      },
      {
        event_type: 'database_query_error',
        timestamp: '2026-10-07T09:02:30Z',
        user: 'app_backend',
        source_ip: '10.0.2.15',
        status: 'error',
        message: 'Connection string failed with password="SecretP@ssword2026!" in connection pool',
      },
    ],
  },
  null,
  2
);

export const TRIGGER_DEMO_CSV = `event_type,timestamp,user,source_ip,destination_ip,destination_port,bytes,status,new_role,message
api_request,2026-10-07T08:00:00Z,service_runner,10.0.1.15,10.0.2.20,443,1204,success,,Routine health check ping to microservice mesh
database_backup_sync,2026-10-07T08:05:00Z,db_admin_sync,10.10.4.100,192.168.50.25,5432,45000000,success,,Nightly database snapshot replication to internal cold storage
user_login,2026-10-07T08:15:10Z,j.miller,198.51.100.45,192.0.2.1,443,,failure,,Failed password verification for console login
user_login,2026-10-07T08:15:45Z,j.miller,198.51.100.45,192.0.2.1,443,,failure,,Invalid credential provided
user_login,2026-10-07T08:16:30Z,j.miller,198.51.100.45,192.0.2.1,443,,failure,,Failed login retry attempt 3
user_login,2026-10-07T08:17:15Z,j.miller,198.51.100.45,192.0.2.1,443,,failure,,Authentication error - incorrect passcode
user_login,2026-10-07T08:18:02Z,j.miller,198.51.100.45,192.0.2.1,443,,failure,,Fifth consecutive failed login from host
user_login,2026-10-07T08:17:30Z,sarah.kim,203.0.113.12,192.0.2.1,443,,success,,Successful single-sign-on authentication
sso_auth,2026-10-07T08:30:00Z,alex.chen,203.0.113.88,192.0.2.1,443,,failure,,SSO attempt failed - bad credentials
sso_auth,2026-10-07T08:30:40Z,alex.chen,203.0.113.88,192.0.2.1,443,,failure,,SSO attempt failed - token rejected
sso_auth,2026-10-07T08:31:20Z,alex.chen,203.0.113.88,192.0.2.1,443,,failure,,SSO attempt failed - bad password hash
sso_auth,2026-10-07T08:32:05Z,alex.chen,203.0.113.88,192.0.2.1,443,,failure,,SSO attempt failed - invalid token
sso_auth,2026-10-07T08:32:50Z,alex.chen,203.0.113.88,192.0.2.1,443,,failure,,SSO attempt failed - lockout imminent
sso_auth,2026-10-07T08:35:10Z,alex.chen,203.0.113.88,192.0.2.1,443,,success,,Session token issued after valid authorization response
iam_role_change,2026-10-07T08:42:00Z,m.rodriguez,10.0.1.44,,,success,administrator,User m.rodriguez promoted to tenant administrator for cluster operations
iam_role_change,2026-10-07T08:44:00Z,t.taylor,10.0.1.44,,,success,billing_viewer,User assigned read-only invoices review role
network_egress,2026-10-07T08:50:00Z,backup_daemon,10.0.5.80,93.184.216.34,443,18454912,success,,High-volume outbound data flow to external destination endpoint
network_connection,2026-10-07T08:52:15Z,workstation_04,10.0.5.82,142.250.190.46,4444,4096,established,,Outbound TCP socket established on non-standard port 4444
app_debug_log,2026-10-07T08:58:00Z,ci_pipeline_bot,10.0.1.99,10.0.1.5,8080,,info,,"Deploy task initialized with AWS key AKIAIOSFODNN7EXAMPLE and header Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.synthetic_signature_token"
database_query_error,2026-10-07T09:02:30Z,app_backend,10.0.2.15,,,error,,"Connection string failed with password=""SecretP@ssword2026!"" in connection pool"`;

export const BENIGN_DEMO_JSON = JSON.stringify(
  {
    events: [
      {
        event_type: 'user_login',
        timestamp: '2026-10-07T09:00:00Z',
        user: 'claire.watson',
        source_ip: '192.168.1.105',
        destination_ip: '10.0.0.5',
        destination_port: 443,
        status: 'success',
        bytes: 850,
        message: 'Standard authentication completed via corporate SSO',
      },
      {
        event_type: 'api_request',
        timestamp: '2026-10-07T09:05:00Z',
        user: 'claire.watson',
        source_ip: '192.168.1.105',
        destination_ip: '10.0.0.8',
        destination_port: 443,
        status: 'success',
        bytes: 3200,
        message: 'Retrieved customer account profile details',
      },
      {
        event_type: 'file_transfer',
        timestamp: '2026-10-07T09:15:00Z',
        user: 'backup_service',
        source_ip: '10.0.10.12',
        destination_ip: '10.0.20.15', // Private RFC 1918
        destination_port: 8443,
        status: 'success',
        bytes: 48000000, // 48 MiB internal transfer - must NOT trigger TG004
        message: 'Nightly archive replica synced across private availability zones',
      },
      {
        event_type: 'iam_role_change',
        timestamp: '2026-10-07T09:30:00Z',
        user: 'security_lead',
        source_ip: '10.0.0.2',
        new_role: 'data_analyst', // Non-privileged role - must NOT trigger TG003
        status: 'success',
        message: 'Granted analytics workspace view permissions to junior hire',
      },
      {
        event_type: 'user_login',
        timestamp: '2026-10-07T09:45:00Z',
        user: 'marcus.vance',
        source_ip: '172.16.5.30', // Private RFC 1918
        destination_ip: '10.0.0.5',
        destination_port: 443,
        status: 'failure', // Isolated failure (only 1 failure, well below 5-failure threshold)
        bytes: 412,
        message: 'Initial bad password attempt',
      },
      {
        event_type: 'user_login',
        timestamp: '2026-10-07T10:10:00Z', // 25 minutes later (> 10m window), normal success
        user: 'marcus.vance',
        source_ip: '172.16.5.30',
        destination_ip: '10.0.0.5',
        destination_port: 443,
        status: 'success',
        bytes: 900,
        message: 'Successful second login after resetting hardware token',
      },
      {
        event_type: 'network_egress',
        timestamp: '2026-10-07T10:30:00Z',
        user: 'web_crawler',
        source_ip: '10.0.1.20',
        destination_ip: '198.51.100.22', // Documentation IP RFC 5737 - must NOT trigger TG004
        destination_port: 443,
        bytes: 25000000,
        status: 'success',
        message: 'Synthetic load test traffic to documentation endpoint',
      },
    ],
  },
  null,
  2
);

export const BENIGN_DEMO_CSV = `event_type,timestamp,user,source_ip,destination_ip,destination_port,bytes,status,new_role,message
user_login,2026-10-07T09:00:00Z,claire.watson,192.168.1.105,10.0.0.5,443,850,success,,Standard authentication completed via corporate SSO
api_request,2026-10-07T09:05:00Z,claire.watson,192.168.1.105,10.0.0.8,443,3200,success,,Retrieved customer account profile details
file_transfer,2026-10-07T09:15:00Z,backup_service,10.0.10.12,10.0.20.15,8443,48000000,success,,Nightly archive replica synced across private availability zones
iam_role_change,2026-10-07T09:30:00Z,security_lead,10.0.0.2,,,success,data_analyst,Granted analytics workspace view permissions to junior hire
user_login,2026-10-07T09:45:00Z,marcus.vance,172.16.5.30,10.0.0.5,443,412,failure,,Initial bad password attempt
user_login,2026-10-07T10:10:00Z,marcus.vance,172.16.5.30,10.0.0.5,443,900,success,,Successful second login after resetting hardware token
network_egress,2026-10-07T10:30:00Z,web_crawler,10.0.1.20,198.51.100.22,443,25000000,success,,Synthetic load test traffic to documentation endpoint`;
