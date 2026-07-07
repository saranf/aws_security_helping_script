#!/bin/bash

# ==============================================================================================
# [스크립트 정보]
# 제목: AWS 전사적 통합 보안 진단 도구 (v13 Cross-Platform & Policy Embedded)
# 작성일: 2024. 05. 24
#
# [업데이트 사항]
# 1. [Fix] macOS/Linux 날짜 호환성 패치 적용 (Access Key 수명 계산 로직 개선)
# 2. [Feat] S3 버킷 정책(Policy) 상세 내용을 리포트에 직접 포함 (접기/펼치기 기능)
#
# [진단 범위]
# 1. IAM: [1.8] Access Key, [1.9] MFA
# 2. Network: [3.1~3.4] SG, NACL, RT
# 3. Data: [4.1~4.3] EBS 상세, RDS, S3 상세(정책 포함)
# 4. Availability: [3.7, 4.13]
# 5. EKS: [1.11~4.14]
#
# [실행 방법]
# 1. pip install prowler jq
# 2. aws configure
# 3. chmod +x master_audit_v13.sh && ./master_audit_v13.sh
# ==============================================================================================

# --- [CONFIGURATION] ---
REGION="ap-northeast-2"
CHECK_PORTS="22 3389 3306 5432 27017"
IAM_KEY_MAX_DAYS=90
# -----------------------

DATE_STR=$(date +%Y%m%d_%H%M)
BASE_DIR="./Total_Audit_Result_${DATE_STR}"
mkdir -p "$BASE_DIR/evidence_s3_policies" 

IAM_REPORT="$BASE_DIR/1_IAM_Compliance.md"
NET_REPORT="$BASE_DIR/2_Network_Security.md"
DATA_REPORT="$BASE_DIR/3_Data_Protection.md"
AVAIL_REPORT="$BASE_DIR/4_Availability_Access.md"
EKS_BASE_DIR="$BASE_DIR/5_EKS_Audit_All"
FINAL_REPORT="$BASE_DIR/0_FINAL_EXECUTIVE_REPORT.md"

log() { echo -e "\033[1;32m[INFO]\033[0m $1"; }

echo "========================================================"
echo " 🛡️  AWS 전사적 통합 보안 진단 시작 (v13 Final)"
echo "========================================================"

# ==============================================================================================
# Phase 1. IAM
# ==============================================================================================
log "Step 1. IAM 점검 중..."
cat <<EOF > "$IAM_REPORT"
# 1. IAM 규정 준수
## 1.1 [1.8] Access Key 수명 ($IAM_KEY_MAX_DAYS일)
| 사용자 | Key ID | 경과일 | 상태 | 권고 |
|---|---|---|---|---|
EOF

# [Fix] macOS/Linux 호환 날짜 변환 로직 (기준일 계산)
if date -d "1 day ago" >/dev/null 2>&1; then
    LIMIT_DATE=$(date -d "${IAM_KEY_MAX_DAYS} days ago" +%s)
else
    LIMIT_DATE=$(date -v-${IAM_KEY_MAX_DAYS}d +%s)
fi

USERS=$(aws iam list-users --query "Users[].UserName" --output text)
if [ -n "$USERS" ]; then
    for USER in $USERS; do
        KEYS=$(aws iam list-access-keys --user-name $USER --query "AccessKeyMetadata[].[AccessKeyId, CreateDate, Status]" --output text)
        if [ -z "$KEYS" ]; then continue; fi
        while read -r KEY_ID KEY_DATE STATUS; do
            if [ -z "$KEY_ID" ]; then continue; fi
            
            # [Fix] macOS/Linux 호환 날짜 변환 로직 (키 생성일 계산)
            if date -d "1 day ago" >/dev/null 2>&1; then
                KEY_SEC=$(date -d "$KEY_DATE" +%s) # Linux
            else
                # AWS ISO 8601 포맷 대응 (예: 2023-01-01T10:00:00+00:00)
                KEY_SEC=$(date -j -f "%Y-%m-%dT%H:%M:%S%z" "$KEY_DATE" +%s 2>/dev/null) # macOS
            fi
            
            curr_sec=$(date +%s)
            diff_days=$(( (curr_sec - KEY_SEC) / 86400 ))
            
            if [ $KEY_SEC -lt $LIMIT_DATE ] && [ "$STATUS" == "Active" ]; then
                echo "| \`$USER\` | \`$KEY_ID\` | **${diff_days}일** | 🔴 Active | 교체 |" >> "$IAM_REPORT"
            fi
        done <<< "$KEYS"
    done
fi

cat <<EOF >> "$IAM_REPORT"

## 1.2 [1.9] MFA 미설정
| 사용자 | 상태 | 권고 |
|---|---|---|
EOF
if [ -n "$USERS" ]; then
    for USER in $USERS; do
        MFA=$(aws iam list-mfa-devices --user-name "$USER" --query "MFADevices" --output text)
        LOGIN=$(aws iam get-login-profile --user-name "$USER" 2>/dev/null)
        if [ -n "$LOGIN" ] && [ -z "$MFA" ]; then
            echo "| \`$USER\` | ❌ 미설정 | 설정 필수 |" >> "$IAM_REPORT"
        fi
    done
fi


# ==============================================================================================
# Phase 2. Network Security
# ==============================================================================================
log "Step 2. 네트워크(VPC/SG/NACL) 정밀 점검 중..."
cat <<EOF > "$NET_REPORT"
# 2. 네트워크 보안 상세 리포트
## 2.1 [3.1] 보안 그룹 위험 포트 개방
| 그룹명 | ID | 포트 | 대상 | 위험도 |
|---|---|---|---|---|
EOF
aws ec2 describe-security-groups --region $REGION --output json | jq --arg ports "$CHECK_PORTS" -r '
  ($ports | split(" ") | map(tonumber)) as $target_ports | .SecurityGroups[] | .GroupName as $name | .GroupId as $id | .IpPermissions[] | 
  select(.IpRanges[].CidrIp == "0.0.0.0/0") | select(.FromPort as $fp | $target_ports | index($fp)) |
  "| \($name) | \($id) | \(.FromPort) | 0.0.0.0/0 | 🚨 CRITICAL |"
' >> "$NET_REPORT"

echo "" >> "$NET_REPORT"; echo "## 2.2 [3.2] 미사용 보안 그룹" >> "$NET_REPORT"
echo "| 그룹명 | ID | 설명 | 권고 |" >> "$NET_REPORT"; echo "|---|---|---|---|" >> "$NET_REPORT"
ALL_SGS=$(aws ec2 describe-security-groups --region $REGION --query "SecurityGroups[*].GroupId" --output text | tr '\t' '\n' | sort)
USED_SGS=$(aws ec2 describe-network-interfaces --region $REGION --query "NetworkInterfaces[*].Groups[*].GroupId" --output text | tr '\t' '\n' | sort | uniq)
UNUSED_SGS=$(comm -23 <(echo "$ALL_SGS") <(echo "$USED_SGS"))
for SG_ID in $UNUSED_SGS; do
    SG_INFO=$(aws ec2 describe-security-groups --region $REGION --group-ids $SG_ID --query "SecurityGroups[0].[GroupName, Description]" --output text)
    SG_NAME=$(echo "$SG_INFO" | awk '{print $1}'); if [ "$SG_NAME" != "default" ]; then echo "| $SG_NAME | \`$SG_ID\` | 미사용 | 삭제 |" >> "$NET_REPORT"; fi
done

echo "" >> "$NET_REPORT"; echo "## 2.3 [3.3] 네트워크 ACL 점검" >> "$NET_REPORT"
echo "| NACL ID | VPC ID | 기본여부 | 서브넷 수 | 상태 |" >> "$NET_REPORT"; echo "|---|---|---|---|---|" >> "$NET_REPORT"
aws ec2 describe-network-acls --region $REGION --output json | jq -r '
  .NetworkAcls[] | .NetworkAclId as $id | .VpcId as $vpc | .IsDefault as $def | (.Associations | length) as $subnets |
  "| \($id) | \($vpc) | \($def) | \($subnets)개 | \(if $def then "✅ 기본값" else "⚠️ 커스텀" end) |"
' >> "$NET_REPORT"

echo "" >> "$NET_REPORT"; echo "## 2.4 [3.4] 라우팅 테이블 (퍼블릭 서브넷)" >> "$NET_REPORT"
echo "| RT ID | 대상 | 타겟 | 서브넷 | 상태 |" >> "$NET_REPORT"; echo "|---|---|---|---|---|" >> "$NET_REPORT"
aws ec2 describe-route-tables --region $REGION --output json | jq -r '
  .RouteTables[] | select(.Routes[].GatewayId | startswith("igw-")) | .RouteTableId as $rtb |
  (.Associations[]?.SubnetId // "Main Table") as $sub |
  "| \($rtb) | 0.0.0.0/0 | IGW | \($sub) | 🌐 **Public** |"
' >> "$NET_REPORT"


# ==============================================================================================
# Phase 3. Data Protection (Enhanced Policy Dump)
# ==============================================================================================
log "Step 3. 데이터 암호화 및 S3 정책 추출 중..."

cat <<EOF > "$DATA_REPORT"
# 3. 데이터 보호 상세 리포트

## 3.1 [4.1] EBS 볼륨 암호화 현황
| 볼륨ID | 인스턴스명(ID) | 보안그룹 | 키페어 | 암호화 |
|---|---|---|---|---|
EOF

# EBS 상세 추적
aws ec2 describe-volumes --region $REGION --filters Name=encrypted,Values=false --query "Volumes[*]" --output json | jq -c '.[]' | while read -r vol; do
    VOL_ID=$(echo $vol | jq -r '.VolumeId')
    INST_ID=$(echo $vol | jq -r '.Attachments[0].InstanceId // empty')
    
    if [ -n "$INST_ID" ]; then
        INST_INFO=$(aws ec2 describe-instances --instance-ids $INST_ID --region $REGION --query 'Reservations[0].Instances[0].{Name:Tags[?Key==`Name`]|[0].Value, SG:SecurityGroups[*].GroupId, Key:KeyName}' --output json)
        INST_NAME=$(echo $INST_INFO | jq -r '.Name // "N/A"')
        SG_IDS=$(echo $INST_INFO | jq -r '.SG[]' | tr '\n' ',' | sed 's/,$//')
        KEY_NAME=$(echo $INST_INFO | jq -r '.Key // "N/A"')
        echo "| \`$VOL_ID\` | **$INST_NAME** ($INST_ID) | \`$SG_IDS\` | $KEY_NAME | ❌ 미적용 |" >> "$DATA_REPORT"
    else
        echo "| \`$VOL_ID\` | (Detached) | - | - | ❌ 미적용 |" >> "$DATA_REPORT"
    fi
done

cat <<EOF >> "$DATA_REPORT"

## 3.2 [4.2] RDS 암호화 현황
| DB 식별자 | 엔진 | 상태 | 암호화 |
|---|---|---|---|
EOF
aws rds describe-db-instances --region $REGION --query "DBInstances[?StorageEncrypted==\`false\`].[DBInstanceIdentifier, Engine, DBInstanceStatus]" --output text | while read id eng st; do echo "| \`$id\` | $eng | $st | ❌ 미적용 |" >> "$DATA_REPORT"; done


cat <<EOF >> "$DATA_REPORT"

## 3.3 [4.3] S3 버킷 암호화 및 정책 확인
| 버킷명 | 암호화 설정 | 정책(Policy) 유무 | 비고 |
|---|---|---|---|
EOF

# S3 정책 저장용 변수 초기화
S3_POLICIES_CONTENT=""

BUCKETS=$(aws s3api list-buckets --query "Buckets[].Name" --output text)
if [ -n "$BUCKETS" ]; then
    for BUCKET in $BUCKETS; do
        ENC=$(aws s3api get-bucket-encryption --bucket "$BUCKET" 2>/dev/null)
        if [ -z "$ENC" ]; then ENC_STR="❌ 미적용"; else ENC_STR="✅ 적용됨"; fi
        
        POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query "Policy" --output text 2>/dev/null)
        if [ -n "$POLICY" ] && [ "$POLICY" != "None" ]; then
            POLICY_STR="✅ 있음"
            echo "$POLICY" | jq . > "$BASE_DIR/evidence_s3_policies/${BUCKET}_policy.json"
            
            # [Feature] 리포트에 정책 내용 포함 (접기/펼치기)
            S3_POLICIES_CONTENT+=$'\n<details><summary><strong>'"$BUCKET"' 정책 보기</strong></summary>\n\n```json\n'
            S3_POLICIES_CONTENT+=$(echo "$POLICY" | jq .)
            S3_POLICIES_CONTENT+=$'\n```\n</details>\n'
        else
            POLICY_STR="❌ 없음"
        fi
        
        if [ "$ENC_STR" == "❌ 미적용" ] || [ "$POLICY_STR" == "✅ 있음" ]; then
             echo "| \`$BUCKET\` | $ENC_STR | $POLICY_STR | 확인 |" >> "$DATA_REPORT"
        fi
    done
fi

# 리포트 하단에 정책 내용 추가
if [ -n "$S3_POLICIES_CONTENT" ]; then
    echo "" >> "$DATA_REPORT"
    echo "### 3.4 S3 버킷 정책 상세 내용 (Attached Policies)" >> "$DATA_REPORT"
    echo "$S3_POLICIES_CONTENT" >> "$DATA_REPORT"
fi


# ==============================================================================================
# Phase 4. Availability & Access Control
# ==============================================================================================
log "Step 4. 가용성(S3/RDS) 점검 중..."
cat <<EOF > "$AVAIL_REPORT"
# 4. 가용성 및 접근제어 리포트
## 4.1 [3.7] S3 퍼블릭 액세스 차단 / [4.13] RDS 백업
| 서비스 | 리소스 | 상태 | 권고 |
|---|---|---|---|
EOF
if [ -n "$BUCKETS" ]; then
    for BUCKET in $BUCKETS; do
        BLOCK=$(aws s3api get-public-access-block --bucket "$BUCKET" --query "PublicAccessBlockConfiguration" --output json 2>/dev/null)
        if [ -z "$BLOCK" ]; then echo "| S3 | \`$BUCKET\` | ❌ Open | 차단 활성화 |" >> "$AVAIL_REPORT"; fi
    done
fi
NO_BACKUP=$(aws rds describe-db-instances --region $REGION --query "DBInstances[?BackupRetentionPeriod==\`0\`].[DBInstanceIdentifier]" --output text)
for DB in $NO_BACKUP; do echo "| RDS | \`$DB\` | ❌ No Backup | 백업 활성화 |" >> "$AVAIL_REPORT"; done


# ==============================================================================================
# Phase 5. EKS Audit
# ==============================================================================================
log "Step 5. EKS 클러스터 점검 (Prowler)..."
CLUSTERS=$(aws eks list-clusters --region "$REGION" --query "clusters" --output text)
if [ -n "$CLUSTERS" ]; then
    mkdir -p "$EKS_BASE_DIR"
    for C in $CLUSTERS; do
        log "  >> Cluster: $C"
        CDIR="$EKS_BASE_DIR/$C"; mkdir -p "$CDIR"
        aws eks update-kubeconfig --name "$C" --region "$REGION" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            prowler aws --services eks --region "$REGION" --output-directory "$CDIR" --output-filename "aws_infra" --output-modes csv html --quiet
            prowler kubernetes --output-directory "$CDIR" --output-filename "k8s_internal" --output-modes csv html --quiet
        fi
    done
fi


# ==============================================================================================
# Phase 6. Final Report
# ==============================================================================================
log "Step 6. 최종 요약본 생성..."
cat <<EOF > "$FINAL_REPORT"
# 🛡️ AWS 보안 진단 요약 (Executive Summary)
**점검 일시:** $(date) / **리전:** $REGION

---
## 1. 🔑 IAM ([1.8, 1.9])
EOF
if grep -q "🔴" "$IAM_REPORT"; then grep "🔴" "$IAM_REPORT" >> "$FINAL_REPORT"; else echo "✅ 양호" >> "$FINAL_REPORT"; fi
if grep -q "❌" "$IAM_REPORT"; then grep "❌" "$IAM_REPORT" >> "$FINAL_REPORT"; else echo "✅ MFA 양호" >> "$FINAL_REPORT"; fi

cat <<EOF >> "$FINAL_REPORT"

## 2. 🌐 네트워크 ([3.1 ~ 3.4])
EOF
if grep -q "🚨" "$NET_REPORT"; then grep "🚨" "$NET_REPORT" >> "$FINAL_REPORT"; else echo "✅ 위험 포트 없음" >> "$FINAL_REPORT"; fi
if grep -q "🌐" "$NET_REPORT"; then echo "⚠️ 퍼블릭 서브넷 발견 (상세 참조)" >> "$FINAL_REPORT"; fi

cat <<EOF >> "$FINAL_REPORT"

## 3. 🔒 데이터 ([4.1 ~ 4.3])
EOF
if grep -q "EBS" "$DATA_REPORT"; then echo "⚠️ 암호화 미적용 자산 발견 (상세 참조)" >> "$FINAL_REPORT"; else echo "✅ 암호화 양호" >> "$FINAL_REPORT"; fi

cat <<EOF >> "$FINAL_REPORT"

## 4. 🛡️ 가용성 ([3.7, 4.13])
EOF
if grep -q "❌" "$AVAIL_REPORT"; then echo "⚠️ 가용성/접근제어 취약점 발견 (상세 참조)" >> "$FINAL_REPORT"; else echo "✅ 양호" >> "$FINAL_REPORT"; fi

cat <<EOF >> "$FINAL_REPORT"

## 5. ☸️ EKS ([1.11 ~ 4.14])
EOF
if [ -n "$CLUSTERS" ]; then
    for C in $CLUSTERS; do
        echo "### $C" >> "$FINAL_REPORT"
        FILES=$(find "$EKS_BASE_DIR/$C" -name "*.csv")
        FAIL=0
        if [ -n "$FILES" ]; then
            grep "FAIL" $FILES | while IFS=, read -r line; do
                if [[ "$line" == *"Privileged"* ]] || [[ "$line" == *"Anonymous"* ]] || [[ "$line" == *"ServiceAccount"* ]] || [[ "$line" == *"Admin"* ]]; then
                    DESC=$(echo "$line" | awk -F',' '{print $11}' | cut -c 1-50)...
                    echo "- ❌ FAIL: $DESC" >> "$FINAL_REPORT"
                    ((FAIL++))
                fi
            done
        fi
        if [ $FAIL -eq 0 ]; then echo "✅ 양호" >> "$FINAL_REPORT"; fi
    done
fi

echo "✅ 완료! 👉 $FINAL_REPORT"
