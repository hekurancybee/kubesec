SET join_use_nulls = 1;

WITH
blocked AS
(
    SELECT
        timestamp AS evt_ts,
        namespace, pod_name, container, workload_key,
        pid AS target_pid,
        syscall_name, argument,
        cgroup_id, node_name
    FROM syscall_events
    WHERE action='blocked'
      AND namespace='demo'
      AND pod_name='secure-nginx-765944d6b9-5rbzl'
      AND container='nginx'
    ORDER BY timestamp DESC
    LIMIT 1
),
proc_snap AS
(
    SELECT
        pid,
        argMax(ppid, timestamp) AS ppid,
        argMax(comm, timestamp) AS comm,
        argMax(pcomm, timestamp) AS pcomm,
        argMax(args, timestamp) AS args,
        argMax(timestamp, timestamp) AS last_seen_ts
    FROM process_executions
    WHERE (namespace, pod_name, container, cgroup_id, node_name) IN
          (SELECT namespace, pod_name, container, cgroup_id, node_name FROM blocked)
      AND timestamp <= (SELECT evt_ts FROM blocked)
      AND timestamp >= (SELECT evt_ts FROM blocked) - INTERVAL 5 MINUTE
    GROUP BY pid
),

-- build the chain as columns first (easy), then explode to rows
chain_cols AS
(
    SELECT
        b.evt_ts, b.syscall_name, b.argument,
        p0.pid AS pid0, p0.ppid AS ppid0,
        p1.pid AS pid1, p1.ppid AS ppid1,
        p2.pid AS pid2, p2.ppid AS ppid2,
        p3.pid AS pid3, p3.ppid AS ppid3,
        p4.pid AS pid4, p4.ppid AS ppid4,
        p5.pid AS pid5, p5.ppid AS ppid5
    FROM blocked b
    LEFT JOIN proc_snap p0 ON p0.pid = b.target_pid
    LEFT JOIN proc_snap p1 ON p1.pid = p0.ppid
    LEFT JOIN proc_snap p2 ON p2.pid = p1.ppid
    LEFT JOIN proc_snap p3 ON p3.pid = p2.ppid
    LEFT JOIN proc_snap p4 ON p4.pid = p3.ppid
    LEFT JOIN proc_snap p5 ON p5.pid = p4.ppid
),

-- explode to rows
chain_rows AS
(
    SELECT
        evt_ts, syscall_name, argument,
        arrayJoin(
          arrayZip(
            [0,1,2,3,4,5],
            [pid0,pid1,pid2,pid3,pid4,pid5]
          )
        ) AS z
    FROM chain_cols
)

SELECT
    r.evt_ts,
    r.syscall_name,
    r.argument,
    z.1 AS depth,
    z.2 AS pid,
    ps.ppid,
    ps.comm,
    ps.pcomm,
    ps.args,
    ps.last_seen_ts
FROM chain_rows r
LEFT JOIN proc_snap ps ON ps.pid = z.2
WHERE NOT isNull(z.2)
ORDER BY depth;
