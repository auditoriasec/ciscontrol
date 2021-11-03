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

SELECT
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
'CIS CRITICAL SECURITY CONTROLS' AS "FRAMEWORK"
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
WHERE UPPER(NAME)='SEC_PROTOCOL_ERROR_TRACE_ACTION';
