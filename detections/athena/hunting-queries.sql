-- Athena hunting queries — AWS CloudTrail Threat Detection
--
-- These are retrospective HUNTING queries, not detections. The three deployed
-- detections (see ../cloudwatch/metric-filters.json) alert in near real time.
-- These queries search historical logs in S3 for the same behaviours plus
-- patterns that metric filters cannot express, such as event sequences.
--
-- Prerequisite: a Glue table over the CloudTrail S3 bucket. The CloudTrail
-- console offers "Create Athena table" from the Event history page.
--
-- Replace <TABLE> with your table name and adjust date partitions.
-- Athena bills per byte scanned, so always constrain the partition range.


-- ---------------------------------------------------------------------------
-- 1. Root account usage
-- Mirrors the RootAccountUsage metric filter. Excludes AWS service-invoked
-- activity, which otherwise appears as root and is the first false positive.
-- MITRE T1078.004
-- ---------------------------------------------------------------------------
SELECT
    eventtime,
    eventname,
    awsregion,
    sourceipaddress,
    useragent,
    json_extract_scalar(additionaleventdata, '$.MFAUsed')  AS mfa_used,
    json_extract_scalar(responseelements, '$.ConsoleLogin') AS login_result,
    eventid
FROM <TABLE>
WHERE useridentity.type = 'Root'
  AND useridentity.invokedby IS NULL
  AND eventtype <> 'AwsServiceEvent'
ORDER BY eventtime;


-- ---------------------------------------------------------------------------
-- 2. Privilege escalation, ranked by the privilege actually granted
-- Severity lives in requestParameters.policyArn, not in eventName. The same
-- AttachUserPolicy event is routine with ReadOnlyAccess and critical with
-- IAMFullAccess. This query encodes that distinction, which the deployed
-- metric filter cannot.
-- MITRE T1098.001, T1098.003
-- ---------------------------------------------------------------------------
SELECT
    eventtime,
    eventname,
    useridentity.arn                                        AS actor,
    json_extract_scalar(requestparameters, '$.userName')    AS target_user,
    json_extract_scalar(requestparameters, '$.policyArn')   AS policy_arn,
    sourceipaddress,
    eventid,
    CASE
      WHEN json_extract_scalar(requestparameters, '$.policyArn') LIKE '%AdministratorAccess%' THEN 'CRITICAL'
      WHEN json_extract_scalar(requestparameters, '$.policyArn') LIKE '%IAMFullAccess%'       THEN 'CRITICAL'
      WHEN json_extract_scalar(requestparameters, '$.policyArn') LIKE '%PowerUserAccess%'     THEN 'HIGH'
      WHEN eventname IN ('CreateAccessKey', 'CreateLoginProfile')                             THEN 'HIGH'
      WHEN eventname = 'UpdateAssumeRolePolicy'                                               THEN 'HIGH'
      ELSE 'INFORMATIONAL'
    END AS severity
FROM <TABLE>
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname IN (
        'AttachUserPolicy','AttachRolePolicy','AttachGroupPolicy',
        'PutUserPolicy','PutRolePolicy','PutGroupPolicy',
        'CreatePolicyVersion','SetDefaultPolicyVersion',
        'CreateAccessKey','CreateLoginProfile','UpdateAssumeRolePolicy'
      )
  AND errorcode IS NULL
ORDER BY eventtime;


-- ---------------------------------------------------------------------------
-- 3. CloudTrail tampering, including the S3 log store
-- Extends the deployed filter, which is scoped to cloudtrail.amazonaws.com only
-- and therefore misses PutBucketPolicy against the log bucket. That gap was
-- demonstrated during testing (eventIDs 5bfa1454, 240b1b5e).
-- MITRE T1685.002
-- ---------------------------------------------------------------------------
SELECT
    eventtime,
    eventsource,
    eventname,
    useridentity.arn                                     AS actor,
    COALESCE(
      json_extract_scalar(requestparameters, '$.name'),
      json_extract_scalar(requestparameters, '$.bucketName')
    )                                                    AS target,
    sourceipaddress,
    eventid
FROM <TABLE>
WHERE (
        eventsource = 'cloudtrail.amazonaws.com'
        AND eventname IN ('StopLogging','StartLogging','UpdateTrail',
                          'DeleteTrail','PutEventSelectors')
      )
   OR (
        eventsource = 'kms.amazonaws.com'
        AND eventname IN ('DisableKey','ScheduleKeyDeletion')
      )
   OR (
        eventsource = 's3.amazonaws.com'
        AND eventname IN ('PutBucketPolicy','DeleteBucketPolicy',
                          'PutLifecycleConfiguration','PutBucketAcl',
                          'PutBucketVersioning')
      )
ORDER BY eventtime;


-- ---------------------------------------------------------------------------
-- 4. Stop-then-start logging sequence
-- This is the pattern a metric filter cannot express. Neither StopLogging nor
-- StartLogging is suspicious alone; the pair, from one identity within a short
-- window, creates a bounded gap in the record and then restores normal
-- appearance. Observed during testing: 3c596c6d at 06:06:01 followed by
-- 34c51c39 at 06:09:20, same session, 3 min 19 sec apart.
-- MITRE T1685.002
-- ---------------------------------------------------------------------------
WITH trail_ops AS (
    SELECT
        eventtime,
        eventname,
        useridentity.arn                                  AS actor,
        useridentity.accesskeyid                          AS access_key,
        json_extract_scalar(requestparameters, '$.name')  AS trail_arn,
        eventid
    FROM <TABLE>
    WHERE eventsource = 'cloudtrail.amazonaws.com'
      AND eventname IN ('StopLogging','StartLogging')
)
SELECT
    stop.eventtime                                          AS stopped_at,
    start.eventtime                                         AS restarted_at,
    date_diff('second',
              from_iso8601_timestamp(stop.eventtime),
              from_iso8601_timestamp(start.eventtime))      AS gap_seconds,
    stop.actor,
    stop.trail_arn,
    stop.eventid                                            AS stop_event_id,
    start.eventid                                           AS start_event_id
FROM trail_ops stop
JOIN trail_ops start
  ON  stop.access_key = start.access_key
  AND stop.trail_arn  = start.trail_arn
  AND start.eventtime > stop.eventtime
WHERE stop.eventname  = 'StopLogging'
  AND start.eventname = 'StartLogging'
  AND date_diff('second',
                from_iso8601_timestamp(stop.eventtime),
                from_iso8601_timestamp(start.eventtime)) < 3600
ORDER BY stopped_at;


-- ---------------------------------------------------------------------------
-- 5. Session reconstruction — pivot on the credential, not the username
-- Every action in one login session shares a sessionContext.creationDate.
-- Unlike source IP, this survives an attacker changing networks. During the
-- investigation this tied the IAM escalation and the CloudTrail destruction,
-- 34 minutes apart, to a single console login.
-- ---------------------------------------------------------------------------
SELECT
    eventtime,
    eventname,
    eventsource,
    useridentity.accesskeyid                                   AS access_key,
    useridentity.sessioncontext.attributes.creationdate        AS session_start,
    useridentity.sessioncontext.attributes.mfaauthenticated    AS mfa,
    sourceipaddress,
    readonly,
    eventid
FROM <TABLE>
WHERE useridentity.sessioncontext.attributes.creationdate = '<SESSION_CREATION_DATE>'
ORDER BY eventtime;


-- ---------------------------------------------------------------------------
-- 6. Write events only — noise reduction
-- The single most effective filter in cloud log analysis. During testing,
-- 680 events in the incident window reduced to 11 state-changing events.
-- A two-minute root console session alone produced 127 events, all read-only.
-- ---------------------------------------------------------------------------
SELECT
    eventtime,
    eventname,
    eventsource,
    useridentity.arn      AS actor,
    sourceipaddress,
    errorcode,
    eventid
FROM <TABLE>
WHERE readonly = false
  AND eventtime BETWEEN '<START_ISO8601>' AND '<END_ISO8601>'
ORDER BY eventtime;


-- ---------------------------------------------------------------------------
-- 7. Failed API bursts — enumeration indicator
-- A spike of AccessDenied or UnauthorizedOperation from one identity across
-- many services is what reconnaissance looks like. No deployed detection
-- covers this; see detection-coverage-assessment.md, gap M2.
-- MITRE T1580
-- ---------------------------------------------------------------------------
SELECT
    useridentity.arn                  AS actor,
    sourceipaddress,
    date_trunc('minute', from_iso8601_timestamp(eventtime)) AS minute_bucket,
    COUNT(*)                          AS denied_count,
    COUNT(DISTINCT eventsource)       AS distinct_services,
    array_agg(DISTINCT eventname)     AS attempted_actions
FROM <TABLE>
WHERE errorcode IN ('AccessDenied','UnauthorizedOperation','Client.UnauthorizedOperation')
GROUP BY 1, 2, 3
HAVING COUNT(*) >= 5
ORDER BY denied_count DESC;


-- ---------------------------------------------------------------------------
-- 8. Credential type distribution
-- AKIA prefixes are long-term IAM user keys: no expiry, no MFA. ASIA prefixes
-- are temporary STS credentials. The distinction determines the containment
-- path — deactivating a key does not invalidate ASIA sessions already issued.
-- ---------------------------------------------------------------------------
SELECT
    CASE
      WHEN useridentity.accesskeyid LIKE 'AKIA%' THEN 'AKIA (long-term, MFA-exempt)'
      WHEN useridentity.accesskeyid LIKE 'ASIA%' THEN 'ASIA (temporary STS)'
      ELSE 'other or absent'
    END                          AS credential_type,
    useridentity.arn             AS actor,
    COUNT(*)                     AS event_count,
    MIN(eventtime)               AS first_seen,
    MAX(eventtime)               AS last_seen
FROM <TABLE>
GROUP BY 1, 2
ORDER BY event_count DESC;


-- ---------------------------------------------------------------------------
-- 9. Newly created access keys never subsequently used
-- A created key with no usage is a dormant persistence artifact. Recording
-- this as a negative finding was part of the investigation: key
-- AKIA...D2UY2OVY (eventID 7077c297) was created and never exercised.
-- MITRE T1098.001
-- ---------------------------------------------------------------------------
WITH created AS (
    SELECT
        eventtime AS created_at,
        json_extract_scalar(responseelements, '$.accessKey.accessKeyId') AS new_key,
        json_extract_scalar(requestparameters, '$.userName')             AS target_user,
        useridentity.arn                                                 AS created_by,
        eventid
    FROM <TABLE>
    WHERE eventname = 'CreateAccessKey'
      AND errorcode IS NULL
)
SELECT
    c.created_at,
    c.new_key,
    c.target_user,
    c.created_by,
    c.eventid,
    COUNT(u.eventid) AS times_used
FROM created c
LEFT JOIN <TABLE> u
  ON u.useridentity.accesskeyid = c.new_key
 AND u.eventtime > c.created_at
GROUP BY c.created_at, c.new_key, c.target_user, c.created_by, c.eventid
ORDER BY c.created_at;
