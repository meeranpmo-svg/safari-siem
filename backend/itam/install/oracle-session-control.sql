-- Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
--
-- Session control for Databases -> Long-Running Queries: lets the platform CANCEL a running statement or KILL a session that
-- is hurting the database, AFTER a named DBA approver has approved the request (four-eyes, recorded in the audit trail).
--
-- Run as a DBA (SYS or a DBA account) in the database (multitenant: in the PDB = the service name the platform uses).
-- It creates:
--   ZYB_OPS      a schema that cannot log in. It owns ONE procedure and holds the only powerful grant (ALTER SYSTEM),
--                which nobody can use except through that procedure.
--   ZYB_CONTROL  the login the platform uses for this. CREATE SESSION + EXECUTE on that one procedure - nothing else.
--                The platform refuses to use it if it ever holds any other privilege.
-- The read-only monitoring user (zyb_monitor) is NOT changed and never gets these rights.
--
-- What the procedure refuses, whatever the platform asks:
--   - background / non-user sessions, and the sessions of Oracle and platform accounts (list below + ZYB_OPS.PROTECTED_USERS)
--   - a session whose user is not the one that was approved, or whose SQL_ID changed since (the statement finished and the
--     session is doing something else - nothing is cancelled or killed by mistake)
--   - a SID / serial# that no longer exists
-- Every call (done or refused) is written to ZYB_OPS.ACTION_LOG.
--
-- Change the password. To withdraw the capability at any time: DROP USER zyb_control CASCADE;

CREATE USER zyb_ops NO AUTHENTICATION;                 -- 18c+: a schema nobody can log in to (11g/12c: IDENTIFIED BY <random> ACCOUNT LOCK)
GRANT ALTER SYSTEM TO zyb_ops;                          -- used ONLY inside zyb_ops.session_ctl (definer rights)
GRANT SELECT ON sys.gv_$session TO zyb_ops;             -- direct grant: a definer-rights procedure does not see roles
ALTER USER zyb_ops QUOTA 10M ON users;

CREATE TABLE zyb_ops.protected_users (username VARCHAR2(128) PRIMARY KEY);   -- add your own (application owners, batch accounts …)
CREATE TABLE zyb_ops.action_log (
  at          TIMESTAMP DEFAULT SYSTIMESTAMP,
  caller      VARCHAR2(128) DEFAULT SYS_CONTEXT('USERENV', 'SESSION_USER'),
  mode_       VARCHAR2(10), inst_id NUMBER, sid NUMBER, serial# NUMBER, username VARCHAR2(128), sql_id VARCHAR2(13),
  request_ref VARCHAR2(64), result VARCHAR2(400));

CREATE OR REPLACE PROCEDURE zyb_ops.session_ctl (
  p_mode      IN  VARCHAR2,     -- CANCEL (stop the running statement, 18c+) or KILL (end the session, roll back its transaction)
  p_inst_id   IN  NUMBER,
  p_sid       IN  NUMBER,
  p_serial    IN  NUMBER,
  p_username  IN  VARCHAR2,     -- the user that was approved
  p_sql_id    IN  VARCHAR2,     -- the statement that was approved (NULL = do not check, e.g. an idle session holding locks)
  p_ref       IN  VARCHAR2,     -- the platform's request id, for the log
  p_result    OUT VARCHAR2
) AUTHID DEFINER AS
  v_user  VARCHAR2(128); v_type VARCHAR2(20); v_sql VARCHAR2(13); v_n NUMBER; v_mode VARCHAR2(10) := UPPER(p_mode);
  PROCEDURE done(r VARCHAR2) IS BEGIN
    p_result := r;
    INSERT INTO zyb_ops.action_log (mode_, inst_id, sid, serial#, username, sql_id, request_ref, result) VALUES (v_mode, p_inst_id, p_sid, p_serial, p_username, p_sql_id, SUBSTR(p_ref, 1, 64), SUBSTR(r, 1, 400));
    COMMIT;
  END;
BEGIN
  IF v_mode NOT IN ('CANCEL', 'KILL') THEN done('REFUSED: mode must be CANCEL or KILL'); RETURN; END IF;
  BEGIN
    SELECT username, type, sql_id INTO v_user, v_type, v_sql FROM sys.gv_$session WHERE inst_id = p_inst_id AND sid = p_sid AND serial# = p_serial;
  EXCEPTION WHEN NO_DATA_FOUND THEN done('GONE: the session no longer exists (it ended by itself)'); RETURN;
  END;
  IF v_type <> 'USER' OR v_user IS NULL THEN done('REFUSED: not a user session'); RETURN; END IF;
  IF v_user IN ('SYS', 'SYSTEM', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSRAC', 'DBSNMP', 'GSMADMIN_INTERNAL', 'XDB', 'AUDSYS', 'OUTLN', 'MDSYS', 'CTXSYS', 'ORDSYS', 'WMSYS', 'LBACSYS', 'DVSYS', 'GGSYS', 'ZYB_OPS', 'ZYB_CONTROL', 'ZYB_MONITOR') THEN
    done('REFUSED: ' || v_user || ' is a protected account'); RETURN; END IF;
  SELECT COUNT(*) INTO v_n FROM zyb_ops.protected_users WHERE username = v_user;
  IF v_n > 0 THEN done('REFUSED: ' || v_user || ' is in ZYB_OPS.PROTECTED_USERS'); RETURN; END IF;
  IF v_user <> UPPER(p_username) THEN done('REFUSED: the session now belongs to ' || v_user || ', not ' || UPPER(p_username)); RETURN; END IF;
  IF p_sql_id IS NOT NULL AND NVL(v_sql, '-') <> p_sql_id THEN done('CHANGED: the session is no longer running SQL_ID ' || p_sql_id || ' - nothing done'); RETURN; END IF;
  IF v_mode = 'CANCEL' THEN
    EXECUTE IMMEDIATE 'ALTER SYSTEM CANCEL SQL ''' || TO_CHAR(p_sid) || ',' || TO_CHAR(p_serial) || ',@' || TO_CHAR(p_inst_id) || '''';
    done('DONE: statement cancelled');
  ELSE
    EXECUTE IMMEDIATE 'ALTER SYSTEM KILL SESSION ''' || TO_CHAR(p_sid) || ',' || TO_CHAR(p_serial) || ',@' || TO_CHAR(p_inst_id) || ''' IMMEDIATE';
    done('DONE: session killed (its open transaction is rolled back)');
  END IF;
EXCEPTION WHEN OTHERS THEN done('FAILED: ' || SUBSTR(SQLERRM, 1, 300));
END;
/

CREATE USER zyb_control IDENTIFIED BY "Change-Me-Long-Random-2" DEFAULT TABLESPACE users QUOTA 0 ON users;
GRANT CREATE SESSION TO zyb_control;
GRANT EXECUTE ON zyb_ops.session_ctl TO zyb_control;
-- optional: limit it like the monitoring user
-- ALTER USER zyb_control PROFILE zyb_monitor_prof;
