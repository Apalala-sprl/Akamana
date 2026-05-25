ALTER TABLE machine_monitor_ports ADD COLUMN IF NOT EXISTS sni_host VARCHAR(255) NOT NULL DEFAULT '';

ALTER TABLE machine_monitor_ports ADD UNIQUE KEY IF NOT EXISTS uniq_mmp_port_vhost (machine_id, port, sni_host);

ALTER TABLE machine_monitor_ports DROP INDEX IF EXISTS uniq_machine_monitor_port;
