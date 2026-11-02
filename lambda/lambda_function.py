"""
AWS Lambda Network Anomaly Evaluator
Executes Athena threat queries, evaluates findings against risk thresholds,
and publishes alerts to Amazon SNS.
"""

import json
import logging
import os
import time
from typing import Any, Dict, List
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ATHENA_DATABASE = os.environ.get("ATHENA_DATABASE", "vpc_flow_logs_db")
ATHENA_WORKGROUP = os.environ.get("ATHENA_WORKGROUP", "primary")
QUERY_RESULTS_S3 = os.environ.get("QUERY_RESULTS_S3", "s3://my-athena-query-results/")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")

athena_client = boto3.client("athena")
sns_client = boto3.client("sns")


def execute_athena_query(query: str, database: str = ATHENA_DATABASE) -> str:
    """Submits query to Athena and returns QueryExecutionId."""
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": QUERY_RESULTS_S3},
        WorkGroup=ATHENA_WORKGROUP,
    )
    return response["QueryExecutionId"]


def wait_for_query_completion(query_execution_id: str, max_attempts: int = 30) -> bool:
    """Polls Athena until query succeeds or fails."""
    for _ in range(max_attempts):
        response = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        status = response["QueryExecution"]["Status"]["State"]
        if status in ["SUCCEEDED"]:
            return True
        elif status in ["FAILED", "CANCELLED"]:
            reason = response["QueryExecution"]["Status"].get("StateChangeReason", "Unknown")
            logger.error("Athena query %s failed: %s", query_execution_id, reason)
            return False
        time.sleep(2)
    return False


def get_query_results(query_execution_id: str) -> List[Dict[str, Any]]:
    """Fetches and parses rows from Athena query results."""
    response = athena_client.get_query_results(QueryExecutionId=query_execution_id)
    rows = response["ResultSet"]["Rows"]
    if len(rows) <= 1:
        return []

    headers = [col["VarCharValue"] for col in rows[0]["Data"]]
    results = []
    for row in rows[1:]:
        row_dict = {}
        for idx, col in enumerate(row["Data"]):
            row_dict[headers[idx]] = col.get("VarCharValue", "")
        results.append(row_dict)
    return results


def publish_threat_alert(anomalies: List[Dict[str, Any]]) -> None:
    """Dispatches SNS alert for detected anomalous network activity."""
    if not SNS_TOPIC_ARN or not anomalies:
        return

    subject = f"[CRITICAL] Network Traffic Anomaly Detected: {len(anomalies)} Threat Vectors"
    message = json.dumps(
        {
            "alert": "Network Traffic Anomaly Alert",
            "threat_count": len(anomalies),
            "findings": anomalies,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        indent=2,
    )

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=message,
    )
    logger.info("Published SNS threat alert for %d anomalies", len(anomalies))


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entrypoint triggered by CloudWatch scheduled events."""
    logger.info("Executing scheduled VPC Flow Logs security anomaly sweep")

    port_scan_query = """
    SELECT srcaddr, count(distinct dstport) as ports, count(*) as rejects
    FROM vpc_flow_logs
    WHERE action = 'REJECT'
    GROUP BY srcaddr
    HAVING count(distinct dstport) > 10
    ORDER BY ports DESC
    LIMIT 10;
    """

    query_id = execute_athena_query(port_scan_query)
    completed = wait_for_query_completion(query_id)

    if not completed:
        return {"statusCode": 500, "body": json.dumps({"status": "ERROR", "query_id": query_id})}

    anomalies = get_query_results(query_id)
    if anomalies:
        publish_threat_alert(anomalies)

    return {
        "statusCode": 200,
        "body": json.dumps({"status": "SUCCESS", "anomalies_detected": len(anomalies), "records": anomalies}),
    }
