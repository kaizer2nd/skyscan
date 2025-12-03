import logging
from typing import Dict, Any, List
import json
import asyncio
import random
import hashlib

logger = logging.getLogger(__name__)


class CloudScanner:
    """Professional cloud infrastructure vulnerability scanner"""
    
    def __init__(self):
        self.metadata_endpoints = {
            'aws': 'http://169.254.169.254/latest/meta-data/',
            'azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'gcp': 'http://metadata.google.internal/computeMetadata/v1/'
        }
        self.compliance_frameworks = ['CIS', 'NIST', 'PCI-DSS', 'HIPAA', 'SOC2']
    
    async def scan_cloud_config(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Professional cloud configuration vulnerability scan
        
        Args:
            config: Cloud configuration dictionary (simulated for demo)
        
        Returns:
            Comprehensive scan results with findings and compliance status
        """
        findings = []
        
        # Generate varied configuration if none provided
        if not config:
            config = self._get_demo_config()
        
        # Comprehensive security checks
        findings.extend(self._check_storage_permissions(config.get('storage', {})))
        findings.extend(self._check_network_exposure(config.get('network', {})))
        findings.extend(self._check_iam_policies(config.get('iam', {})))
        findings.extend(self._check_encryption(config.get('encryption', {})))
        findings.extend(self._check_logging(config.get('logging', {})))
        findings.extend(self._check_password_policy(config.get('iam', {}).get('password_policy', {})))
        
        # Compliance assessment
        compliance_status = self._assess_compliance(findings, config.get('compliance', {}))
        
        result = {
            'scan_type': 'cloud',
            'total_findings': len(findings),
            'findings': findings,
            'severity_breakdown': self._calculate_severity_breakdown(findings),
            'compliance_status': compliance_status,
            'risk_score': self._calculate_risk_score(findings),
            'recommendations': self._generate_cloud_recommendations(findings),
            'status': 'completed'
        }
        
        logger.info(f"Cloud scan completed: {len(findings)} findings, risk score: {result['risk_score']}")
        return result
    
    def _check_logging(self, logging: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check logging and monitoring configurations"""
        findings = []
        
        if not logging.get('cloudtrail_enabled'):
            findings.append({
                'type': 'Audit & Compliance',
                'severity': 'HIGH',
                'resource': 'CloudTrail',
                'description': 'CloudTrail is not enabled for audit logging',
                'recommendation': 'Enable CloudTrail to track API calls and user activity',
                'compliance_impact': ['PCI-DSS', 'SOC2', 'HIPAA']
            })
        
        if not logging.get('flow_logs_enabled'):
            findings.append({
                'type': 'Network Monitoring',
                'severity': 'MEDIUM',
                'resource': 'VPC Flow Logs',
                'description': 'VPC Flow Logs are disabled',
                'recommendation': 'Enable VPC Flow Logs for network traffic analysis',
                'compliance_impact': ['CIS', 'NIST']
            })
        
        if not logging.get('s3_access_logging'):
            findings.append({
                'type': 'Data Access Monitoring',
                'severity': 'MEDIUM',
                'resource': 'S3 Access Logs',
                'description': 'S3 access logging is not configured',
                'recommendation': 'Enable S3 server access logging to track bucket access',
                'compliance_impact': ['PCI-DSS']
            })
        
        retention = logging.get('retention_days', 0)
        if retention < 90:
            findings.append({
                'type': 'Log Retention',
                'severity': 'MEDIUM',
                'resource': 'Log Retention Policy',
                'description': f'Log retention period is only {retention} days',
                'recommendation': 'Increase log retention to at least 90 days for security analysis',
                'compliance_impact': ['SOC2', 'HIPAA']
            })
        
        return findings
    
    def _check_password_policy(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check IAM password policy"""
        findings = []
        
        min_length = policy.get('minimum_length', 0)
        if min_length < 14:
            findings.append({
                'type': 'Password Policy',
                'severity': 'MEDIUM',
                'resource': 'IAM Password Policy',
                'description': f'Password minimum length is {min_length}, below recommended 14 characters',
                'recommendation': 'Set minimum password length to 14 or more characters',
                'compliance_impact': ['CIS', 'NIST']
            })
        
        if not policy.get('require_symbols'):
            findings.append({
                'type': 'Password Policy',
                'severity': 'MEDIUM',
                'resource': 'IAM Password Policy',
                'description': 'Password policy does not require special characters',
                'recommendation': 'Require at least one special character in passwords',
                'compliance_impact': ['NIST']
            })
        
        max_age = policy.get('max_age_days')
        if not max_age or max_age > 90:
            findings.append({
                'type': 'Password Policy',
                'severity': 'LOW',
                'resource': 'IAM Password Policy',
                'description': 'Password expiration not configured or too long',
                'recommendation': 'Set password expiration to 90 days maximum',
                'compliance_impact': ['PCI-DSS']
            })
        
        return findings
    
    def _assess_compliance(self, findings: List[Dict[str, Any]], compliance_config: Dict[str, Any]) -> Dict[str, Any]:
        """Assess compliance status"""
        frameworks = compliance_config.get('frameworks', [])
        compliance_status = {}
        
        for framework in self.compliance_frameworks:
            impacted_findings = [f for f in findings if framework in f.get('compliance_impact', [])]
            compliance_status[framework] = {
                'enabled': framework in frameworks,
                'issues_found': len(impacted_findings),
                'status': 'Non-Compliant' if impacted_findings else 'Compliant'
            }
        
        return compliance_status
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> int:
        """Calculate overall risk score (0-100)"""
        severity_weights = {'CRITICAL': 25, 'HIGH': 10, 'MEDIUM': 3, 'LOW': 1}
        total_score = sum(severity_weights.get(f.get('severity', 'LOW'), 1) for f in findings)
        return min(100, total_score)
    
    def _generate_cloud_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high_count = sum(1 for f in findings if f.get('severity') == 'HIGH')
        
        if critical_count > 0:
            recommendations.append(f'URGENT: Address {critical_count} critical security findings immediately')
        
        if high_count > 0:
            recommendations.append(f'High Priority: Remediate {high_count} high-severity issues within 7 days')
        
        # Specific recommendations based on finding types
        finding_types = set(f.get('type') for f in findings)
        
        if 'IAM Security' in finding_types:
            recommendations.append('Implement least-privilege access and enable MFA for all users')
        
        if 'Storage Misconfiguration' in finding_types or 'Missing Encryption' in finding_types:
            recommendations.append('Enable encryption for all storage resources and restrict public access')
        
        if 'Network Exposure' in finding_types:
            recommendations.append('Review and tighten security group rules, eliminate 0.0.0.0/0 where possible')
        
        if 'Audit & Compliance' in finding_types:
            recommendations.append('Enable comprehensive logging and monitoring across all services')
        
        recommendations.append('Conduct regular security audits and penetration testing')
        recommendations.append('Implement automated compliance scanning in CI/CD pipeline')
        
        return recommendations
    
    def _get_demo_config(self) -> Dict[str, Any]:
        """Generate varied, realistic cloud configuration for testing"""
        # Generate variations based on current time for different results
        import time
        seed = int(time.time() / 100)  # Changes every ~100 seconds
        random.seed(seed)
        
        # Randomize bucket configurations
        bucket_configs = [
            {'name': 'app-logs-prod', 'public_access': False, 'encryption': True, 'versioning': True},
            {'name': 'static-assets', 'public_access': random.choice([True, False]), 'encryption': random.choice([True, False]), 'versioning': False},
            {'name': 'user-uploads', 'public_access': False, 'encryption': random.choice([True, False]), 'versioning': True},
            {'name': 'backups-archive', 'public_access': False, 'encryption': True, 'versioning': True},
            {'name': 'temp-storage', 'public_access': random.choice([True, False]), 'encryption': False, 'versioning': False},
        ]
        
        # Randomize security group rules
        sg_rules = [
            {'port': 22, 'source': random.choice(['0.0.0.0/0', '10.0.0.0/8', '192.168.1.0/24'])},
            {'port': 80, 'source': '0.0.0.0/0'},
            {'port': 443, 'source': '0.0.0.0/0'},
            {'port': 3306, 'source': random.choice(['10.0.0.0/8', '0.0.0.0/0'])},
            {'port': 5432, 'source': random.choice(['10.0.0.0/8', '172.16.0.0/12'])},
        ]
        
        # Randomize IAM users
        iam_users = [
            {'name': 'admin-user', 'mfa_enabled': random.choice([True, False]), 'permissions': ['*:*:*'], 'last_activity': random.choice(['2 days ago', '30 days ago', '90 days ago'])},
            {'name': 'developer', 'mfa_enabled': True, 'permissions': ['s3:*', 'ec2:*'], 'last_activity': '1 day ago'},
            {'name': 'ci-cd-bot', 'mfa_enabled': False, 'permissions': ['s3:*', 'ecr:*', 'ecs:*'], 'last_activity': '3 hours ago'},
            {'name': 'backup-service', 'mfa_enabled': False, 'permissions': ['s3:*', 'glacier:*'], 'last_activity': '12 hours ago'},
        ]
        
        # Randomize encryption settings
        volumes = [
            {'id': 'vol-001', 'encrypted': True, 'type': 'gp3', 'size': 100},
            {'id': 'vol-002', 'encrypted': random.choice([True, False]), 'type': 'gp2', 'size': 50},
            {'id': 'vol-003', 'encrypted': False, 'type': 'io1', 'size': 200},
            {'id': 'vol-004', 'encrypted': random.choice([True, False]), 'type': 'gp3', 'size': 500},
        ]
        
        # Select random subsets
        return {
            'storage': {
                'buckets': random.sample(bucket_configs, random.randint(3, 5))
            },
            'network': {
                'security_groups': [
                    {
                        'name': 'web-sg',
                        'inbound_rules': random.sample(sg_rules, random.randint(3, 5))
                    },
                    {
                        'name': 'database-sg',
                        'inbound_rules': [r for r in sg_rules if r['port'] in [3306, 5432, 22]]
                    }
                ]
            },
            'iam': {
                'users': random.sample(iam_users, random.randint(2, 4)),
                'password_policy': {
                    'minimum_length': random.choice([8, 12, 14]),
                    'require_symbols': random.choice([True, False]),
                    'require_numbers': True,
                    'require_uppercase': random.choice([True, False]),
                    'max_age_days': random.choice([90, 180, 365, None])
                }
            },
            'encryption': {
                'ebs_volumes': random.sample(volumes, random.randint(2, 4)),
                'kms_keys': random.randint(1, 5),
                'default_encryption': random.choice([True, False])
            },
            'logging': {
                'cloudtrail_enabled': random.choice([True, False]),
                'flow_logs_enabled': random.choice([True, False]),
                's3_access_logging': random.choice([True, False]),
                'retention_days': random.choice([7, 30, 90, 365])
            },
            'compliance': {
                'frameworks': random.sample(self.compliance_frameworks, random.randint(1, 3))
            }
        }
    
    def _check_storage_permissions(self, storage: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Comprehensive storage security checks"""
        findings = []
        
        for bucket in storage.get('buckets', []):
            bucket_name = bucket['name']
            
            if bucket.get('public_access'):
                findings.append({
                    'type': 'Storage Misconfiguration',
                    'severity': 'CRITICAL',
                    'resource': bucket_name,
                    'description': f"Bucket '{bucket_name}' allows public access - potential data leak",
                    'recommendation': 'Block all public access unless explicitly required for static content',
                    'compliance_impact': ['HIPAA', 'PCI-DSS', 'SOC2']
                })
            
            if not bucket.get('encryption'):
                findings.append({
                    'type': 'Missing Encryption',
                    'severity': 'HIGH',
                    'resource': bucket_name,
                    'description': f"Bucket '{bucket_name}' lacks server-side encryption",
                    'recommendation': 'Enable AES-256 or AWS KMS encryption',
                    'compliance_impact': ['PCI-DSS', 'HIPAA']
                })
            
            if not bucket.get('versioning'):
                findings.append({
                    'type': 'Data Protection',
                    'severity': 'MEDIUM',
                    'resource': bucket_name,
                    'description': f"Versioning disabled on bucket '{bucket_name}'",
                    'recommendation': 'Enable versioning for data recovery and audit trails',
                    'compliance_impact': ['SOC2']
                })
        
        return findings
    
    def _check_network_exposure(self, network: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Professional network security group assessment"""
        findings = []
        
        for sg in network.get('security_groups', []):
            sg_name = sg['name']
            
            for rule in sg.get('inbound_rules', []):
                port = rule.get('port')
                source = rule.get('source')
                
                # SSH exposure
                if source == '0.0.0.0/0' and port == 22:
                    findings.append({
                        'type': 'Network Exposure',
                        'severity': 'CRITICAL',
                        'resource': sg_name,
                        'description': f"SSH (port 22) exposed to internet in '{sg_name}'",
                        'recommendation': 'Restrict SSH to corporate VPN or bastion host IP ranges',
                        'compliance_impact': ['CIS', 'NIST', 'PCI-DSS']
                    })
                
                # Database exposure
                if source == '0.0.0.0/0' and port in [3306, 5432, 1433, 27017]:
                    db_type = {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 27017: 'MongoDB'}.get(port)
                    findings.append({
                        'type': 'Network Exposure',
                        'severity': 'CRITICAL',
                        'resource': sg_name,
                        'description': f"{db_type} database (port {port}) exposed to internet",
                        'recommendation': f'Restrict {db_type} access to application tier only',
                        'compliance_impact': ['PCI-DSS', 'HIPAA', 'SOC2']
                    })
                
                # Management ports
                if source == '0.0.0.0/0' and port in [3389, 5900, 5901]:
                    service = {3389: 'RDP', 5900: 'VNC', 5901: 'VNC'}.get(port)
                    findings.append({
                        'type': 'Network Exposure',
                        'severity': 'CRITICAL',
                        'resource': sg_name,
                        'description': f"{service} remote access (port {port}) exposed to internet",
                        'recommendation': f'Use VPN or bastion host for {service} access',
                        'compliance_impact': ['CIS', 'NIST']
                    })
                
                # Overly broad private ranges
                if source in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] and port in [3306, 5432]:
                    findings.append({
                        'type': 'Network Exposure',
                        'severity': 'MEDIUM',
                        'resource': sg_name,
                        'description': f"Database port {port} accessible from entire private network",
                        'recommendation': 'Narrow source to specific application subnet',
                        'compliance_impact': ['CIS']
                    })
        
        return findings
    
    def _check_iam_policies(self, iam: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Comprehensive IAM security assessment"""
        findings = []
        
        for user in iam.get('users', []):
            user_name = user['name']
            
            # MFA check
            if not user.get('mfa_enabled'):
                severity = 'CRITICAL' if '*:*:*' in user.get('permissions', []) else 'HIGH'
                findings.append({
                    'type': 'IAM Security',
                    'severity': severity,
                    'resource': user_name,
                    'description': f"User '{user_name}' lacks multi-factor authentication",
                    'recommendation': 'Enable MFA for all users, especially privileged accounts',
                    'compliance_impact': ['CIS', 'PCI-DSS', 'SOC2']
                })
            
            # Overly permissive policies
            if '*:*:*' in user.get('permissions', []):
                findings.append({
                    'type': 'IAM Security',
                    'severity': 'CRITICAL',
                    'resource': user_name,
                    'description': f"User '{user_name}' has full admin access with wildcard permissions",
                    'recommendation': 'Apply least-privilege principle, grant specific permissions only',
                    'compliance_impact': ['CIS', 'NIST', 'PCI-DSS', 'HIPAA']
                })
            
            # Inactive users
            last_activity = user.get('last_activity', '')
            if '90 days' in last_activity or '30 days' in last_activity:
                findings.append({
                    'type': 'IAM Security',
                    'severity': 'MEDIUM',
                    'resource': user_name,
                    'description': f"User '{user_name}' inactive for {last_activity}",
                    'recommendation': 'Disable or remove inactive user accounts',
                    'compliance_impact': ['SOC2', 'NIST']
                })
            
            # Service accounts without MFA
            if 'bot' in user_name.lower() or 'service' in user_name.lower():
                if not user.get('mfa_enabled'):
                    findings.append({
                        'type': 'IAM Security',
                        'severity': 'HIGH',
                        'resource': user_name,
                        'description': f"Service account '{user_name}' should use role-based access instead of user credentials",
                        'recommendation': 'Migrate to IAM roles for service-to-service authentication',
                        'compliance_impact': ['CIS', 'SOC2']
                    })
        
        return findings
    
    def _check_encryption(self, encryption: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Comprehensive encryption configuration checks"""
        findings = []
        
        for volume in encryption.get('ebs_volumes', []):
            if not volume.get('encrypted'):
                volume_size = volume.get('size', 0)
                severity = 'CRITICAL' if volume_size > 100 else 'HIGH'
                findings.append({
                    'type': 'Missing Encryption',
                    'severity': severity,
                    'resource': volume['id'],
                    'description': f"EBS volume '{volume['id']}' ({volume_size}GB) lacks encryption",
                    'recommendation': 'Enable encryption-at-rest using AWS KMS',
                    'compliance_impact': ['PCI-DSS', 'HIPAA', 'SOC2']
                })
        
        # Check for default encryption
        if not encryption.get('default_encryption'):
            findings.append({
                'type': 'Encryption Policy',
                'severity': 'MEDIUM',
                'resource': 'Account Settings',
                'description': 'Default EBS encryption is not enabled for the account',
                'recommendation': 'Enable default encryption to automatically encrypt new volumes',
                'compliance_impact': ['CIS']
            })
        
        # KMS key management
        kms_keys = encryption.get('kms_keys', 0)
        if kms_keys == 0:
            findings.append({
                'type': 'Key Management',
                'severity': 'MEDIUM',
                'resource': 'KMS',
                'description': 'No customer-managed KMS keys found',
                'recommendation': 'Use customer-managed keys for better control and auditability',
                'compliance_impact': ['SOC2', 'HIPAA']
            })
        
        return findings
    
    def _calculate_severity_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity breakdown"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        
        return breakdown
