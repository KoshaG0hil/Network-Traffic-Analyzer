-- ==============================================================================
-- Athena External Table Definition for AWS VPC Flow Logs (Version 2)
-- Partitioned by date (dt: YYYY-MM-DD)
-- ==============================================================================

CREATE EXTERNAL TABLE IF NOT EXISTS vpc_flow_logs (
  version INT,
  account_id STRING,
  interface_id STRING,
  srcaddr STRING,
  dstaddr STRING,
  srcport INT,
  dstport INT,
  protocol INT,
  packets BIGINT,
  bytes BIGINT,
  start BIGINT,
  `end` BIGINT,
  action STRING,
  log_status STRING
)
PARTITIONED BY (dt STRING)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
WITH SERDEPROPERTIES (
  'input.regex' = '^(\\d+)\\s+(\\d+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\S+)\\s+(\\S+)$'
)
LOCATION 's3://${VPC_FLOW_LOGS_BUCKET}/AWSLogs/${AWS_ACCOUNT_ID}/vpcflowlogs/${AWS_REGION}/'
TBLPROPERTIES (
  'projection.enabled' = 'true',
  'projection.dt.type' = 'date',
  'projection.dt.range' = 'NOW-90DAYS,NOW',
  'projection.dt.format' = 'yyyy/MM/dd',
  'projection.dt.interval' = '1',
  'projection.dt.interval.unit' = 'DAYS',
  'storage.location.template' = 's3://${VPC_FLOW_LOGS_BUCKET}/AWSLogs/${AWS_ACCOUNT_ID}/vpcflowlogs/${AWS_REGION}/${dt}'
);
