ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_type_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_type_check CHECK (
    type IN (
        'cpu_high', 'ram_high', 'disk_high', 'service_restart', 'agent_offline',
        'UPTIME_DOWN', 'UPTIME_RECOVERED', 'SSL_EXPIRING', 'UPTIME_SLOW'
    )
);
