-- ==============================================================================
-- Sample Threat Hunting & Anomaly Detection Queries for Athena
-- ==============================================================================

-- 1. Detect Inbound SSH / RDP Port Scanning (High REJECT volume across distinct ports)
SELECT
    srcaddr AS attacker_ip,
    COUNT(DISTINCT dstport) AS distinct_ports_targeted,
    COUNT(*) AS total_rejected_packets,
    MIN(from_unixtime(start)) AS first_seen,
    MAX(from_unixtime(`end`)) AS last_seen
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND dt >= date_format(current_date - interval '1' day, '%Y/%m/%d')
GROUP BY srcaddr
HAVING COUNT(DISTINCT dstport) > 10
ORDER BY distinct_ports_targeted DESC
LIMIT 50;


-- 2. Detect Large Data Exfiltration Spikes (Outbound bytes > 500 MB to public IPs)
SELECT
    srcaddr AS internal_host_ip,
    dstaddr AS external_destination_ip,
    SUM(bytes) / (1024 * 1024) AS total_megabytes_transferred,
    protocol,
    dstport
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND srcaddr LIKE '10.%'  -- internal private IP
  AND NOT (dstaddr LIKE '10.%' OR dstaddr LIKE '172.16.%' OR dstaddr LIKE '192.168.%')
  AND dt >= date_format(current_date - interval '1' day, '%Y/%m/%d')
GROUP BY srcaddr, dstaddr, protocol, dstport
HAVING SUM(bytes) > 500 * 1024 * 1024
ORDER BY total_megabytes_transferred DESC
LIMIT 25;


-- 3. Top Rejected Ingress Traffic by Country / Source IP
SELECT
    srcaddr,
    dstport,
    COUNT(*) AS rejection_count,
    SUM(bytes) AS bytes_dropped
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND dt >= date_format(current_date - interval '7' day, '%Y/%m/%d')
GROUP BY srcaddr, dstport
ORDER BY rejection_count DESC
LIMIT 20;


-- 4. Potential Cryptomining or Non-Standard Port Outbound Traffic
SELECT
    srcaddr,
    dstaddr,
    dstport,
    COUNT(*) AS connection_count,
    SUM(bytes) AS bytes_transferred
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND dstport IN (3333, 4444, 5555, 6666, 7777, 8333, 9999, 14444)
  AND dt >= date_format(current_date - interval '3' day, '%Y/%m/%d')
GROUP BY srcaddr, dstaddr, dstport
ORDER BY connection_count DESC;
