/*
    ########################################################################
    ####                                                                  ##
    #### Autor: Rafael Silva                                              ##
    #### Cargo: Auditor Sênior | Cyber Secyrity                           ##
    #### Data: 02/11/2021                                                 ##
    #### Script: Automação | Hardening CIS Security Control | Oracle DB   ##
    ####                                                                  ##
    ########################################################################
*/

/*
    ########################################################################
    ######################## 2 Oracle Parameter Settings ###################
    ########################################################################
*/

/*
    ########################################################################
    ########################### 2.1 Listener Settings ######################
    ########################################################################
*/

/*
    ####################################################################################
    ###########2.1.1 Ensure 'SECURE_CONTROL_' Is Set In 'listener.ora' (Automated) #####
    ####################################################################################
*/

SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.1' AS "CONTROLE"
,'Ensure AUDIT_SYS_OPERATIONS Is Set to TRUE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'TRUE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'TRUE' THEN 'OK'
    ELSE 'NOK'
END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME) = 'AUDIT_SYS_OPERATIONS'

/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.2' AS "CONTROLE"
,'Ensure AUDIT_TRAIL Is Set to DB, XML, OS, DB,EXTENDED, or XML,EXTENDED (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'DB, XML, OS, DB,EXTENDED, or XML,EXTENDED' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) ='DB, XML, OS, DB,EXTENDED' THEN 'OK'
    WHEN UPPER(VALUE) = 'XML,EXTENDED (Automated)' THEN 'OK'
    ELSE 'NOK' END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='AUDIT_TRAIL'

/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.3' AS "CONTROLE"
,'Ensure GLOBAL_NAMES Is Set to TRUE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'TRUE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) ='TRUE' THEN 'OK'
    ELSE 'NOK' END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='GLOBAL_NAMES'

/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.4' AS "CONTROLE"
,'Ensure O7_DICTIONARY_ACCESSIBILITY Is Set to FALSE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'FALSE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) ='FALSE' THEN 'OK'
    ELSE 'NOK' END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='GLOBAL_NAMES'

/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.5' AS "CONTROLE"
,'Ensure OS_ROLES Is Set to FALSE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'FALSE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) ='FALSE' THEN 'OK'
    ELSE 'NOK' END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='OS_ROLES'

/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.6' AS "CONTROLE"
,'Ensure REMOTE_LISTENER Is Empty (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'NULL' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) IS NULL THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='REMOTE_LISTENER' AND VALUE IS NOT NULL


/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.7' AS "CONTROLE"
,'Ensure REMOTE_LOGIN_PASSWORDFILE Is Set to NONE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'NONE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'NONE' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='REMOTE_LOGIN_PASSWORDFILE'

/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.8' AS "CONTROLE"
,'Ensure REMOTE_OS_AUTHENT Is Set to FALSE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'FALSE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'FALSE' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='REMOTE_OS_AUTHENT'


/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.9' AS "CONTROLE"
,'Ensure REMOTE_OS_ROLES Is Set to FALSE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'FALSE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'FALSE' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='REMOTE_OS_ROLES'


/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.10' AS "CONTROLE"
,'Ensure SEC_CASE_SENSITIVE_LOGON Is Set to TRUE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'TRUE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'TRUE' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='SEC_CASE_SENSITIVE_LOGON'

/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.11' AS "CONTROLE"
,'Ensure SEC_MAX_FAILED_LOGIN_ATTEMPTS Is 3 or Less(Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'<= 3' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) <= 3 THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='SEC_MAX_FAILED_LOGIN_ATTEMPTS'

/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.12' AS "CONTROLE"
,'Ensure SEC_PROTOCOL_ERROR_FURTHER_ACTION Is Set to (DROP,3) (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'(DROP,3)' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = '(DROP,3)' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='SEC_PROTOCOL_ERROR_FURTHER_ACTION'

/*
    ########################################################################
    #### CIS CONTROL - CRITICAL SECURITY CONTROLS - ORACLE DATABASE ########
    ########################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.13' AS "CONTROLE"
,'Ensure SEC_PROTOCOL_ERROR_TRACE_ACTION Is Set to LOG (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'LOG' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'LOG' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='SEC_PROTOCOL_ERROR_TRACE_ACTION'

/*
    ############################################################################################
    #### 2.2.14 Ensure 'SEC_RETURN_SERVER_RELEASE_BANNER' Is Set to 'FALSE' (Automated) ########
    ############################################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.14' AS "CONTROLE"
,'Ensure SEC_RETURN_SERVER_RELEASE_BANNER Is Set to FALSE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'FALSE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'FALSE' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='SEC_RETURN_SERVER_RELEASE_BANNER'

/*
    ############################################################################################
    ############# 2.2.15 Ensure 'SQL92_SECURITY' Is Set to 'TRUE' (Automated) ##################
    ############################################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.15' AS "CONTROLE"
,'Ensure SQL92_SECURITY Is Set to TRUE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'TRUE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'TRUE' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='SQL92_SECURITY'

/*
    ############################################################################################
    ############# 2.2.16 Ensure '_trace_files_public' Is Set to 'FALSE' (Automated) ############
    ############################################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.16' AS "CONTROLE"
,'Ensure _trace_files_public Is Set to FALSE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'TRUE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'TRUE' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE NAME='_trace_files_public'

/*
    ############################################################################################
    ############# 2.2.17 Ensure 'RESOURCE_LIMIT' Is Set to 'TRUE' (Automated) ##################
    ############################################################################################
*/

UNION
SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'2.2' AS "ID"
,'Database Settings' AS "DOMÍNIO"
,'2.2.17' AS "CONTROLE"
,'Ensure RESOURCE_LIMIT Is Set to TRUE (Automated)' AS "DESCRIÇÃO"
,UPPER(VALUE) AS "RESULTADO IDENTIFICADO"
,'TRUE' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE
    WHEN UPPER(VALUE) = 'TRUE' THEN 'OK'
    ELSE 'NOK'
 END AS "VALIDACAO"
FROM V$SYSTEM_PARAMETER
WHERE UPPER(NAME)='RESOURCE_LIMIT'

/*
    ############################################################################################
    ################## 3 Oracle Connection and Login Restrictions ##############################
    ############################################################################################
*/

/*
    ############################################################################################
    ############# 3.1 Ensure 'FAILED_LOGIN_ATTEMPTS' Is Less than or Equal to '5' ##############
    ############################################################################################
*/

UNION
SELECT 
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'3' AS "ID"
,'Oracle Connection and Login Restrictions' AS "DOMÍNIO"
,'3.1' AS "CONTROLE"
,'Ensure FAILED_LOGIN_ATTEMPTS Is Less than or Equal to 5' AS "DESCRIÇÃO"
,P.PROFILE||' -> '|| P.LIMIT AS "RESULTADO IDENTIFICADO"
,'5' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE WHEN P.LIMIT = '5' THEN 'OK' ELSE 'NOK' END AS "VALIDACAO"
FROM DBA_PROFILES P
WHERE TO_NUMBER(DECODE(P.LIMIT,
'DEFAULT',(SELECT DISTINCT
DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
FROM DBA_PROFILES
WHERE PROFILE='DEFAULT'
AND RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS'),
'UNLIMITED','9999',
P.LIMIT)) > 5
AND P.RESOURCE_NAME = 'FAILED_LOGIN_ATTEMPTS'
AND EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE ) 

/*
    ########################################################################################################
    ############# 3.2 Ensure 'PASSWORD_LOCK_TIME' Is Greater than or Equal to '1' (Automated) ##############
    ########################################################################################################
*/

UNION

SELECT 
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'3' AS "ID"
,'Oracle Connection and Login Restrictions' AS "DOMÍNIO"
,'3.2' AS "CONTROLE"
,'Ensure PASSWORD_LOCK_TIME Is Greater than or Equal to 1 (Automated)' AS "DESCRIÇÃO"
,P.PROFILE||' -> '|| P.LIMIT AS "RESULTADO IDENTIFICADO"
,'>= 1' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE WHEN P.LIMIT = '1' THEN 'OK' ELSE 'NOK' END AS "VALIDACAO"
FROM DBA_PROFILES P
WHERE TO_NUMBER(DECODE(P.LIMIT,
'DEFAULT',(SELECT DISTINCT
DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
FROM DBA_PROFILES
WHERE PROFILE='DEFAULT'
AND RESOURCE_NAME='PASSWORD_LOCK_TIME'),
'UNLIMITED','9999',
P.LIMIT)) < 1
AND P.RESOURCE_NAME = 'PASSWORD_LOCK_TIME'
AND EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE )

UNION

/*
    ########################################################################################################
    ############# 3.3 Ensure 'PASSWORD_LIFE_TIME' Is Less than or Equal to '90'(Automated) #################
    ########################################################################################################
*/

SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'3' AS "ID"
,'Oracle Connection and Login Restrictions' AS "DOMÍNIO"
,'3.3' AS "CONTROLE"
,'Ensure PASSWORD_LIFE_TIME Is Less than or Equal to 90(Automated)' AS "DESCRIÇÃO"
,P.PROFILE||' -> '|| P.LIMIT AS "RESULTADO IDENTIFICADO"
,'<= 90' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE WHEN P.LIMIT = '90' THEN 'OK' ELSE 'NOK' END AS "VALIDACAO"
FROM DBA_PROFILES P
WHERE TO_NUMBER(DECODE(P.LIMIT,
'DEFAULT',(SELECT DISTINCT
DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
FROM DBA_PROFILES
WHERE PROFILE='DEFAULT'
AND RESOURCE_NAME='PASSWORD_LIFE_TIME'),
'UNLIMITED','9999',P.LIMIT)) > 90 AND
P.RESOURCE_NAME = 'PASSWORD_LIFE_TIME' AND
EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE )

/*
    ############################################################################################################
    ############# 3.4 Ensure 'PASSWORD_REUSE_MAX' Is Greater than or Equal to '20' (Automated) #################
    ############################################################################################################
*/

UNION

SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'3' AS "ID"
,'Oracle Connection and Login Restrictions' AS "DOMÍNIO"
,'3.4' AS "CONTROLE"
,'Ensure PASSWORD_REUSE_MAX Is Greater than or Equal to 20 (Automated)' AS "DESCRIÇÃO"
,P.PROFILE||' -> '|| P.LIMIT AS "RESULTADO IDENTIFICADO"
,'<= 20' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE WHEN P.LIMIT = '90' THEN 'OK' ELSE 'NOK' END AS "VALIDACAO"
FROM DBA_PROFILES P
WHERE TO_NUMBER(DECODE(P.LIMIT,
'DEFAULT',(SELECT DISTINCT
DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
FROM DBA_PROFILES
WHERE PROFILE='DEFAULT'
AND RESOURCE_NAME='PASSWORD_REUSE_MAX'),
'UNLIMITED','9999',P.LIMIT)) < 20 AND
P.RESOURCE_NAME = 'PASSWORD_REUSE_MAX' AND
EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE )

/*
    ##############################################################################################################
    ############# 3.5 Ensure 'PASSWORD_REUSE_TIME' Is Greater than or Equal to '365' (Automated) #################
    ##############################################################################################################
*/

UNION

SELECT 
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'3' AS "ID"
,'Oracle Connection and Login Restrictions' AS "DOMÍNIO"
,'3.5' AS "CONTROLE"
,'Ensure PASSWORD_REUSE_TIME Is Greater than or Equal to 365 (Automated)' AS "DESCRIÇÃO"
,P.PROFILE||' -> '|| P.LIMIT AS "RESULTADO IDENTIFICADO"
,'>= 365' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE WHEN P.LIMIT = '90' THEN 'OK' ELSE 'NOK' END AS "VALIDACAO"
FROM DBA_PROFILES P
WHERE TO_NUMBER(DECODE(P.LIMIT,
'DEFAULT',(SELECT DISTINCT
DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
FROM DBA_PROFILES
WHERE PROFILE='DEFAULT'
AND RESOURCE_NAME='PASSWORD_REUSE_TIME'),
'UNLIMITED','9999',P.LIMIT)) < 365 AND
P.RESOURCE_NAME = 'PASSWORD_REUSE_TIME' AND
EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE )

/*
    ##############################################################################################################
    ############# 3.6 Ensure 'PASSWORD_GRACE_TIME' Is Less than or Equal to '5'(Automated) #######################
    ##############################################################################################################
*/

UNION

SELECT 
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'3' AS "ID"
,'Oracle Connection and Login Restrictions' AS "DOMÍNIO"
,'3.6' AS "CONTROLE"
,'Ensure PASSWORD_GRACE_TIME Is Less than or Equal to 5 (Automated)' AS "DESCRIÇÃO"
,P.PROFILE||' -> '|| P.LIMIT AS "RESULTADO IDENTIFICADO"
,'<= 5' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE WHEN P.LIMIT = '5' THEN 'OK' ELSE 'NOK' END AS "VALIDACAO"
FROM DBA_PROFILES P
WHERE TO_NUMBER(DECODE(P.LIMIT,
'DEFAULT',(SELECT DISTINCT
DECODE(LIMIT,'UNLIMITED',9999,LIMIT)
FROM DBA_PROFILES
WHERE PROFILE='DEFAULT'
AND RESOURCE_NAME='PASSWORD_GRACE_TIME'),
'UNLIMITED','9999',P.LIMIT)) > 5 AND
P.RESOURCE_NAME = 'PASSWORD_GRACE_TIME' AND
EXISTS ( SELECT 'X' FROM DBA_USERS U WHERE U.PROFILE = P.PROFILE )

/*
    ##############################################################################################################
    ############# 3.7 Ensure 'PASSWORD_VERIFY_FUNCTION' Is Set for All Profiles (Automated) ######################
    ##############################################################################################################
*/

UNION

SELECT
(select instance_name from v$instance) AS "INSTANCIA"
,(select host_name from v$instance) AS "HOSTNAME"
,(select version from v$instance) AS "VERSION"
,'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
,'ORACLE DATABASE' AS "TECNOLOGIA"
,'3' AS "ID"
,'Oracle Connection and Login Restrictions' AS "DOMÍNIO"
,'3.7' AS "CONTROLE"
,'Ensure PASSWORD_VERIFY_FUNCTION Is Set for All Profiles (Automated)' AS "DESCRIÇÃO"
,P.PROFILE||' -> '|| P.LIMIT AS "RESULTADO IDENTIFICADO"
,'<= 5' AS "RESULDADO ESPERADO"
,TO_CHAR(SYSDATE,'YYYY-MM-DD HH24:MI:SS') AS "HORARIO"
,CASE WHEN P.LIMIT != 'NULL' THEN 'OK' ELSE 'NOK' END AS "VALIDACAO"
FROM DBA_PROFILES P
WHERE DECODE(P.LIMIT,
'DEFAULT',(SELECT LIMIT
FROM DBA_PROFILES
WHERE PROFILE='DEFAULT'
AND RESOURCE_NAME = P.RESOURCE_NAME),
LIMIT) = 'NULL'
AND P.RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
AND EXISTS ( SELECT 'X'
FROM DBA_USERS U
WHERE U.PROFILE = P.PROFILE );
