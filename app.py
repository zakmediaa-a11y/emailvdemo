import re
import dns.resolver
import socket
import time
import random
import streamlit as st
import pandas as pd
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import io
import os
import psycopg2
from datetime import datetime, date
import plotly.express as px
import plotly.graph_objects as go

@dataclass
class EmailVerificationResult:
    email: str
    status: str
    syntax_valid: bool
    domain_exists: bool
    mx_records_exist: bool
    smtp_verified: Optional[bool]
    is_catch_all: Optional[bool]
    is_disposable: bool
    is_role_based: bool
    is_free_provider: bool
    mx_records: List[str]
    details: List[str]
    confidence_score: int
    deliverable: bool

class EmailVerifier:
    def __init__(self):
        self.disposable_domains = {
            'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
            'throwaway.email', 'yopmail.com', 'temp-mail.org', 'getnada.com',
            'trashmail.com', 'fakeinbox.com', 'maildrop.cc', 'sharklasers.com',
        }
        
        self.role_prefixes = {
            'admin', 'info', 'support', 'sales', 'contact', 'help', 'service',
            'office', 'noreply', 'no-reply', 'webmaster', 'postmaster',
        }
        
        self.free_providers = {
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
            'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com',
        }
    
    def validate_syntax(self, email: str) -> Tuple[bool, str]:
        if not email or '@' not in email:
            return False, "Missing @ symbol"
        if email.count('@') > 1:
            return False, "Multiple @ symbols"
        
        try:
            local, domain = email.split('@')
        except:
            return False, "Invalid format"
        
        if not local or len(local) > 64:
            return False, "Invalid local part length"
        if local.startswith('.') or local.endswith('.'):
            return False, "Local part cannot start/end with dot"
        if '..' in local:
            return False, "Consecutive dots"
        if not domain or len(domain) > 255:
            return False, "Invalid domain length"
        
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return False, "Invalid email format"
        
        return True, "Valid syntax"
    
    def check_domain_exists(self, domain: str) -> bool:
        try:
            socket.gethostbyname(domain)
            return True
        except:
            return False
    
    def get_mx_records(self, domain: str) -> List[str]:
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            sorted_mx = sorted(mx_records, key=lambda x: x.preference)
            return [str(r.exchange).rstrip('.') for r in sorted_mx]
        except:
            return []
    
    def smtp_verify(self, email: str, mx_host: str, timeout: int = 15) -> Tuple[Optional[bool], str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((mx_host, 25))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if not banner.startswith('220'):
                sock.close()
                return None, f"Invalid banner"
            
            sock.send(b'EHLO verify.local\r\n')
            time.sleep(0.5)
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if not response.startswith('250'):
                sock.send(b'HELO verify.local\r\n')
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if not response.startswith('250'):
                    sock.close()
                    return None, f"HELO failed"
            
            sender = random.choice(['verify@gmail.com', 'check@yahoo.com'])
            sock.send(f'MAIL FROM:<{sender}>\r\n'.encode())
            time.sleep(0.5)
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if not response.startswith('250'):
                sock.close()
                return None, f"MAIL FROM rejected"
            
            sock.send(f'RCPT TO:<{email}>\r\n'.encode())
            time.sleep(0.5)
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.send(b'QUIT\r\n')
            sock.close()
            
            response_code = response[:3]
            
            if response_code in ['250', '251']:
                return True, "Mailbox verified"
            elif response_code in ['550', '551', '552', '553']:
                return False, "Mailbox does not exist"
            else:
                return None, f"Inconclusive ({response_code})"
                
        except Exception as e:
            return None, f"Error: {str(e)[:40]}"
    
    def check_catch_all(self, domain: str, mx_host: str) -> Optional[bool]:
        random_local = f"nonexistent{random.randint(100000, 999999)}test{random.randint(1000, 9999)}"
        random_email = f"{random_local}@{domain}"
        try:
            result, _ = self.smtp_verify(random_email, mx_host, timeout=10)
            return result is True
        except:
            return None
    
    def is_disposable(self, domain: str) -> bool:
        return domain.lower() in self.disposable_domains
    
    def is_role_based(self, email: str) -> bool:
        local_part = email.split('@')[0].lower()
        return local_part in self.role_prefixes
    
    def is_free_provider(self, domain: str) -> bool:
        return domain.lower() in self.free_providers
    
    def calculate_confidence(self, result: 'EmailVerificationResult') -> int:
        score = 0
        if result.syntax_valid:
            score += 10
        if result.domain_exists:
            score += 10
        if result.mx_records_exist:
            score += 20
        if result.smtp_verified is True:
            score += 50
        elif result.smtp_verified is False:
            return 0
        if result.is_catch_all:
            score -= 15
        if result.is_disposable:
            score = min(score, 30)
        if result.is_role_based:
            score -= 5
        return max(0, min(100, score))
    
    def verify(self, email: str, check_smtp: bool = True, check_catch_all: bool = True) -> EmailVerificationResult:
        email = email.strip().lower()
        details = []
        
        syntax_valid, syntax_msg = self.validate_syntax(email)
        if not syntax_valid:
            return EmailVerificationResult(
                email=email, status='INVALID', syntax_valid=False,
                domain_exists=False, mx_records_exist=False, smtp_verified=None,
                is_catch_all=None, is_disposable=False, is_role_based=False,
                is_free_provider=False, mx_records=[], details=[syntax_msg],
                confidence_score=0, deliverable=False
            )
        
        domain = email.split('@')[1]
        is_disposable = self.is_disposable(domain)
        is_role_based = self.is_role_based(email)
        is_free_provider = self.is_free_provider(domain)
        
        if is_disposable:
            details.append("Disposable email")
        if is_role_based:
            details.append("Role-based address")
        
        domain_exists = self.check_domain_exists(domain)
        if not domain_exists:
            details.append("Domain does not exist")
            return EmailVerificationResult(
                email=email, status='INVALID', syntax_valid=True,
                domain_exists=False, mx_records_exist=False, smtp_verified=None,
                is_catch_all=None, is_disposable=is_disposable,
                is_role_based=is_role_based, is_free_provider=is_free_provider,
                mx_records=[], details=details, confidence_score=10, deliverable=False
            )
        
        mx_records = self.get_mx_records(domain)
        mx_records_exist = len(mx_records) > 0
        
        if not mx_records_exist:
            details.append("No MX records")
            return EmailVerificationResult(
                email=email, status='INVALID', syntax_valid=True,
                domain_exists=True, mx_records_exist=False, smtp_verified=None,
                is_catch_all=None, is_disposable=is_disposable,
                is_role_based=is_role_based, is_free_provider=is_free_provider,
                mx_records=[], details=details, confidence_score=20, deliverable=False
            )
        
        smtp_verified = None
        if check_smtp:
            smtp_verified, smtp_detail = self.smtp_verify(email, mx_records[0])
            details.append(smtp_detail)
        
        is_catch_all = None
        if check_catch_all and mx_records and smtp_verified is not False:
            is_catch_all = self.check_catch_all(domain, mx_records[0])
            if is_catch_all:
                details.append("Catch-all domain")
        
        if smtp_verified is False:
            status = 'INVALID'
            deliverable = False
        elif smtp_verified is True and not is_disposable:
            status = 'VALID'
            deliverable = True
        elif is_disposable or is_catch_all:
            status = 'RISKY'
            deliverable = smtp_verified is True
        else:
            status = 'UNKNOWN'
            deliverable = False
        
        result = EmailVerificationResult(
            email=email, status=status, syntax_valid=syntax_valid,
            domain_exists=domain_exists, mx_records_exist=mx_records_exist,
            smtp_verified=smtp_verified, is_catch_all=is_catch_all,
            is_disposable=is_disposable, is_role_based=is_role_based,
            is_free_provider=is_free_provider, mx_records=mx_records,
            details=details, confidence_score=0, deliverable=deliverable
        )
        
        result.confidence_score = self.calculate_confidence(result)
        return result
    
    def generate_email_patterns(self, first_name: str, last_name: str, domain: str) -> List[Dict[str, str]]:
        first = first_name.lower().strip()
        last = last_name.lower().strip()
        
        patterns = [
            (f"{first}{last}@{domain}", "firstlast"),
            (f"{last}{first}@{domain}", "lastfirst"),
            (f"{first}_{last}@{domain}", "first_last"),
            (f"{last}_{first}@{domain}", "last_first"),
            (f"{first}.{last}@{domain}", "first.last"),
            (f"{last}.{first}@{domain}", "last.first"),
            (f"{first}-{last}@{domain}", "first-last"),
            (f"{last}-{first}@{domain}", "last-first"),
            (f"{first[0]}{last}@{domain}", "flast"),
            (f"{first}{last[0]}@{domain}", "firstl"),
            (f"{last[0]}{first}@{domain}", "lfirst"),
            (f"{last}{first[0]}@{domain}", "lastf"),
            (f"{first}@{domain}", "first"),
            (f"{last}@{domain}", "last"),
            (f"{first[0]}.{last}@{domain}", "f.last"),
            (f"{first}.{last[0]}@{domain}", "first.l"),
            (f"{last}.{first[0]}@{domain}", "last.f"),
            (f"{last[0]}.{first}@{domain}", "l.first"),
            (f"{first}_{last[0]}@{domain}", "first_l"),
            (f"{last}_{first[0]}@{domain}", "last_f"),
            (f"{first[0]}_{last}@{domain}", "f_last"),
            (f"{last[0]}_{first}@{domain}", "l_first"),
            (f"{last[0]}-{first}@{domain}", "l-first"),
            (f"{first[0]}-{last}@{domain}", "f-last"),
            (f"{first}-{last[0]}@{domain}", "first-l"),
            (f"{last}-{first[0]}@{domain}", "last-f"),
        ]
        
        return [{"email": email, "pattern": pattern} for email, pattern in patterns]
    
    def verify_bulk_concurrent(self, emails: List[str], max_workers: int = 5, check_smtp: bool = True, 
                                check_catch_all: bool = True, progress_callback=None) -> List[EmailVerificationResult]:
        results = []
        total = len(emails)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_email = {
                executor.submit(self.verify, email, check_smtp, check_catch_all): (i, email) 
                for i, email in enumerate(emails)
            }
            
            for future in as_completed(future_to_email):
                i, email = future_to_email[future]
                try:
                    result = future.result()
                    results.append((i, result))
                    if progress_callback:
                        progress_callback(len(results), total, email)
                except Exception as e:
                    error_result = EmailVerificationResult(
                        email=email, status='ERROR', syntax_valid=False,
                        domain_exists=False, mx_records_exist=False, smtp_verified=None,
                        is_catch_all=None, is_disposable=False, is_role_based=False,
                        is_free_provider=False, mx_records=[], 
                        details=[f"Error: {str(e)}"], confidence_score=0, deliverable=False
                    )
                    results.append((i, error_result))
                    if progress_callback:
                        progress_callback(len(results), total, email)
        
        results.sort(key=lambda x: x[0])
        return [r[1] for r in results]

def get_db_connection():
    try:
        conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
        return conn
    except Exception as e:
        st.error(f"Database connection error: {str(e)}")
        return None

def save_verification_to_db(result: EmailVerificationResult, batch_id: str = None, verification_type: str = 'manual'):
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO verification_history 
            (email, status, syntax_valid, domain_exists, mx_records_exist, smtp_verified, 
             is_catch_all, is_disposable, is_role_based, is_free_provider, 
             confidence_score, deliverable, details, batch_id, verification_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            result.email, result.status, result.syntax_valid, result.domain_exists,
            result.mx_records_exist, result.smtp_verified, result.is_catch_all,
            result.is_disposable, result.is_role_based, result.is_free_provider,
            result.confidence_score, result.deliverable, '; '.join(result.details),
            batch_id, verification_type
        ))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False

def update_daily_stats(status: str, is_disposable: bool, is_role_based: bool):
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cur = conn.cursor()
        today = date.today()
        
        cur.execute("""
            INSERT INTO verification_stats (date, total_verifications)
            VALUES (%s, 1)
            ON CONFLICT (date) 
            DO UPDATE SET 
                total_verifications = verification_stats.total_verifications + 1,
                updated_at = CURRENT_TIMESTAMP
        """, (today,))
        
        if status == 'VALID':
            cur.execute("""
                UPDATE verification_stats 
                SET valid_count = valid_count + 1
                WHERE date = %s
            """, (today,))
        elif status == 'INVALID':
            cur.execute("""
                UPDATE verification_stats 
                SET invalid_count = invalid_count + 1
                WHERE date = %s
            """, (today,))
        elif status == 'RISKY':
            cur.execute("""
                UPDATE verification_stats 
                SET risky_count = risky_count + 1
                WHERE date = %s
            """, (today,))
        
        if is_disposable:
            cur.execute("""
                UPDATE verification_stats 
                SET disposable_count = disposable_count + 1
                WHERE date = %s
            """, (today,))
        
        if is_role_based:
            cur.execute("""
                UPDATE verification_stats 
                SET role_based_count = role_based_count + 1
                WHERE date = %s
            """, (today,))
        
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        conn.close()

@st.cache_resource
def get_verifier():
    return EmailVerifier()

st.set_page_config(page_title="Email Verification Tool", page_icon="📧", layout="wide")

st.title("📧 Professional Email Verification & Finder Tool")
st.markdown("### Find and verify email addresses with SMTP validation!")

verifier = get_verifier()

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "✅ Verify Emails - Manual",
    "✅ Verify Emails - CSV",
    "🔍 Find Emails - Manual",
    "🔍 Find Emails - CSV",
    "🧹 Clean & Deduplicate",
    "📊 History & Analytics"
])

with tab1:
    st.markdown("### Enter emails to verify (one per line or comma-separated)")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        verify_manual_input = st.text_area(
            "Email Addresses",
            placeholder="user1@gmail.com\nuser2@yahoo.com\nuser3@example.com",
            height=200,
            key="verify_manual_input"
        )
    
    with col2:
        verify_manual_delay = st.slider(
            "Delay Between Checks (seconds)",
            min_value=0.0,
            max_value=5.0,
            value=1.0,
            step=0.5,
            key="verify_manual_delay"
        )
        save_to_history = st.checkbox("💾 Save to History", value=True, key="verify_manual_save")
        verify_manual_btn = st.button("🚀 Verify Emails", type="primary", key="verify_manual_btn")
    
    if verify_manual_btn:
        if not verify_manual_input or not verify_manual_input.strip():
            st.error("❌ Please enter at least one email address")
        else:
            emails_text = verify_manual_input.replace(',', '\n')
            emails = [e.strip() for e in emails_text.split('\n') if e.strip()]
            
            if not emails:
                st.error("❌ No valid emails found in input")
            else:
                results = []
                total = len(emails)
                batch_id = f"manual_{int(time.time())}" if save_to_history else None
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for i, email in enumerate(emails):
                    status_text.text(f"Verifying {i+1}/{total}: {email}")
                    progress_bar.progress((i + 1) / total)
                    
                    result = verifier.verify(email, check_smtp=True, check_catch_all=True)
                    
                    if save_to_history:
                        save_verification_to_db(result, batch_id, 'manual')
                        update_daily_stats(result.status, result.is_disposable, result.is_role_based)
                    
                    results.append({
                        'Email': result.email,
                        'Status': result.status,
                        'Deliverable': 'Yes' if result.deliverable else 'No',
                        'Confidence': f"{result.confidence_score}%",
                        'SMTP_Verified': 'Yes' if result.smtp_verified else 'No' if result.smtp_verified is False else 'Unknown',
                        'Disposable': 'Yes' if result.is_disposable else 'No',
                        'Role_Based': 'Yes' if result.is_role_based else 'No',
                        'Free_Provider': 'Yes' if result.is_free_provider else 'No',
                        'Catch_All': 'Yes' if result.is_catch_all else 'No' if result.is_catch_all is False else 'Unknown',
                        'Details': '; '.join(result.details)
                    })
                    
                    if i < total - 1 and verify_manual_delay > 0:
                        time.sleep(verify_manual_delay)
                
                df = pd.DataFrame(results)
                
                valid = sum(1 for r in results if r['Status'] == 'VALID')
                invalid = sum(1 for r in results if r['Status'] == 'INVALID')
                risky = sum(1 for r in results if r['Status'] == 'RISKY')
                
                st.success(f"""
✅ Verification Complete!
━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Results: {total} emails processed

Status Breakdown:
  ✅ Valid:   {valid} ({valid/total*100:.1f}%)
  ❌ Invalid: {invalid} ({invalid/total*100:.1f}%)
  ⚠️  Risky:   {risky} ({risky/total*100:.1f}%)
━━━━━━━━━━━━━━━━━━━━━━━━━━
                """)
                
                st.dataframe(df, use_container_width=True)
                
                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download CSV",
                    data=csv,
                    file_name="verification_results.csv",
                    mime="text/csv"
                )

with tab2:
    st.markdown("### Upload CSV with existing emails to verify")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        verify_csv_file = st.file_uploader("Upload CSV File", type=["csv"], key="verify_csv_file")
        verify_csv_column = st.text_input("Email Column Name", value="email", key="verify_csv_column")
        verify_csv_export = st.radio(
            "Export Options",
            ["Full Results", "Valid Only (including catch-all)", "Valid Only (excluding catch-all)", "All Options"],
            key="verify_csv_export"
        )
    
    with col2:
        use_concurrent = st.checkbox("⚡ Use Concurrent Processing (faster)", value=True, key="verify_csv_concurrent")
        if use_concurrent:
            max_workers = st.slider("Concurrent Workers", min_value=1, max_value=10, value=5, key="verify_csv_workers")
        else:
            verify_csv_delay = st.slider(
                "Delay Between Checks (seconds)",
                min_value=0.0,
                max_value=5.0,
                value=1.0,
                step=0.5,
                key="verify_csv_delay"
            )
        save_csv_to_history = st.checkbox("💾 Save to History", value=True, key="verify_csv_save")
        verify_csv_btn = st.button("🚀 Verify Emails", type="primary", key="verify_csv_btn")
    
    if verify_csv_btn:
        if verify_csv_file is None:
            st.error("❌ Please upload a CSV file")
        else:
            try:
                df_input = pd.read_csv(verify_csv_file)
                
                if verify_csv_column not in df_input.columns:
                    available_cols = ', '.join(df_input.columns.tolist())
                    st.error(f"❌ Column '{verify_csv_column}' not found. Available: {available_cols}")
                else:
                    emails = df_input[verify_csv_column].dropna().astype(str).tolist()
                    
                    if not emails:
                        st.error(f"❌ No emails found in column '{verify_csv_column}'")
                    else:
                        total = len(emails)
                        results_data = []
                        batch_id = f"csv_{int(time.time())}" if save_csv_to_history else None
                        
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        if use_concurrent:
                            def update_progress(completed, total_count, current_email):
                                status_text.text(f"Verifying: {completed}/{total_count} completed ({current_email})")
                                progress_bar.progress(completed / total_count)
                            
                            verification_results = verifier.verify_bulk_concurrent(
                                emails, 
                                max_workers=max_workers, 
                                check_smtp=True, 
                                check_catch_all=True, 
                                progress_callback=update_progress
                            )
                            
                            for result in verification_results:
                                if save_csv_to_history:
                                    save_verification_to_db(result, batch_id, 'csv')
                                    update_daily_stats(result.status, result.is_disposable, result.is_role_based)
                                
                                results_data.append({
                                    'Status': result.status,
                                    'Deliverable': 'Yes' if result.deliverable else 'No',
                                    'Confidence': f"{result.confidence_score}%",
                                    'SMTP_Verified': 'Yes' if result.smtp_verified else 'No' if result.smtp_verified is False else 'Unknown',
                                    'Disposable': 'Yes' if result.is_disposable else 'No',
                                    'Role_Based': 'Yes' if result.is_role_based else 'No',
                                    'Free_Provider': 'Yes' if result.is_free_provider else 'No',
                                    'Catch_All': 'Yes' if result.is_catch_all else 'No' if result.is_catch_all is False else 'Unknown',
                                    'Details': '; '.join(result.details)
                                })
                        else:
                            for i, email in enumerate(emails):
                                status_text.text(f"Verifying {i+1}/{total}: {email}")
                                progress_bar.progress((i + 1) / total)
                                
                                result = verifier.verify(email, check_smtp=True, check_catch_all=True)
                                
                                if save_csv_to_history:
                                    save_verification_to_db(result, batch_id, 'csv')
                                    update_daily_stats(result.status, result.is_disposable, result.is_role_based)
                                
                                results_data.append({
                                    'Status': result.status,
                                    'Deliverable': 'Yes' if result.deliverable else 'No',
                                    'Confidence': f"{result.confidence_score}%",
                                    'SMTP_Verified': 'Yes' if result.smtp_verified else 'No' if result.smtp_verified is False else 'Unknown',
                                    'Disposable': 'Yes' if result.is_disposable else 'No',
                                    'Role_Based': 'Yes' if result.is_role_based else 'No',
                                    'Free_Provider': 'Yes' if result.is_free_provider else 'No',
                                    'Catch_All': 'Yes' if result.is_catch_all else 'No' if result.is_catch_all is False else 'Unknown',
                                    'Details': '; '.join(result.details)
                                })
                                
                                if i < total - 1 and verify_csv_delay > 0:
                                    time.sleep(verify_csv_delay)
                        
                        results_df = pd.DataFrame(results_data)
                        final_df = pd.concat([df_input, results_df], axis=1)
                        
                        valid = sum(1 for r in results_data if r['Status'] == 'VALID')
                        invalid = sum(1 for r in results_data if r['Status'] == 'INVALID')
                        risky = sum(1 for r in results_data if r['Status'] == 'RISKY')
                        
                        st.success(f"""
✅ Verification Complete!
━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Results: {total} emails processed

Status Breakdown:
  ✅ Valid:   {valid} ({valid/total*100:.1f}%)
  ❌ Invalid: {invalid} ({invalid/total*100:.1f}%)
  ⚠️  Risky:   {risky} ({risky/total*100:.1f}%)
━━━━━━━━━━━━━━━━━━━━━━━━━━
                        """)
                        
                        st.dataframe(final_df, use_container_width=True)
                        
                        csv_full = final_df.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="📥 Download Full Results CSV",
                            data=csv_full,
                            file_name="verification_full.csv",
                            mime="text/csv",
                            key="download_full"
                        )
                        
                        if verify_csv_export in ["Valid Only (including catch-all)", "All Options"]:
                            mask = final_df['Status'].isin(['VALID', 'RISKY'])
                            filtered_with = final_df[mask].copy()
                            if len(filtered_with) > 0:
                                csv_with = filtered_with.to_csv(index=False).encode('utf-8')
                                st.download_button(
                                    label="📥 Download Valid (with catch-all) CSV",
                                    data=csv_with,
                                    file_name="verification_valid_with_catchall.csv",
                                    mime="text/csv",
                                    key="download_valid_with"
                                )
                        
                        if verify_csv_export in ["Valid Only (excluding catch-all)", "All Options"]:
                            mask = (final_df['Status'] == 'VALID') & (final_df['Catch_All'] != 'Yes')
                            filtered_no = final_df[mask].copy()
                            if len(filtered_no) > 0:
                                csv_no = filtered_no.to_csv(index=False).encode('utf-8')
                                st.download_button(
                                    label="📥 Download Valid (no catch-all) CSV",
                                    data=csv_no,
                                    file_name="verification_valid_no_catchall.csv",
                                    mime="text/csv",
                                    key="download_valid_no"
                                )
                        
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

with tab3:
    st.markdown("""
### Find email addresses from names and domains
Enter one person per line: `FirstName LastName domain.com`

**Example:**
```
John Doe acme.com
Jane Smith techcorp.io
Bob Johnson startup.co
```

The tool will test **26 different email patterns** and find the correct one!
    """)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        find_manual_input = st.text_area(
            "Names and Domains",
            placeholder="John Doe acme.com\nJane Smith techcorp.io\nBob Johnson startup.co",
            height=200,
            key="find_manual_input"
        )
    
    with col2:
        find_manual_delay = st.slider(
            "Delay Between Checks (seconds)",
            min_value=0.5,
            max_value=5.0,
            value=1.0,
            step=0.5,
            key="find_manual_delay"
        )
        find_manual_btn = st.button("🔍 Find Emails", type="primary", key="find_manual_btn")
    
    if find_manual_btn:
        if not find_manual_input or not find_manual_input.strip():
            st.error("❌ Please enter at least one entry (First Name, Last Name, Domain)")
        else:
            lines = [l.strip() for l in find_manual_input.split('\n') if l.strip()]
            all_results = []
            total_entries = len(lines)
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for entry_idx, line in enumerate(lines):
                status_text.text(f"Processing entry {entry_idx+1}/{total_entries}")
                progress_bar.progress(entry_idx / total_entries)
                
                parts = re.split(r'[,\s]+', line)
                
                if len(parts) < 3:
                    all_results.append({
                        'First_Name': '',
                        'Last_Name': '',
                        'Domain': '',
                        'Found_Email': 'ERROR',
                        'Pattern': '',
                        'Status': 'INVALID',
                        'Deliverable': 'No',
                        'Confidence': '0%',
                        'Details': 'Invalid format - need: FirstName LastName domain.com'
                    })
                    continue
                
                first_name = parts[0]
                last_name = parts[1]
                domain = parts[2]
                
                patterns = verifier.generate_email_patterns(first_name, last_name, domain)
                
                found_email = None
                best_result = None
                pattern_name = ''
                
                for i, pattern_info in enumerate(patterns):
                    email = pattern_info['email']
                    pattern_name = pattern_info['pattern']
                    
                    status_text.text(f"Testing {email}")
                    
                    result = verifier.verify(email, check_smtp=True, check_catch_all=True)
                    
                    if result.smtp_verified is True:
                        found_email = email
                        best_result = result
                        break
                    
                    if best_result is None or (result.confidence_score > best_result.confidence_score):
                        found_email = email
                        best_result = result
                    
                    time.sleep(find_manual_delay)
                
                if best_result:
                    all_results.append({
                        'First_Name': first_name,
                        'Last_Name': last_name,
                        'Domain': domain,
                        'Found_Email': found_email,
                        'Pattern': pattern_name if found_email else 'N/A',
                        'Status': best_result.status,
                        'Deliverable': 'Yes' if best_result.deliverable else 'No',
                        'Confidence': f"{best_result.confidence_score}%",
                        'SMTP_Verified': 'Yes' if best_result.smtp_verified else 'No' if best_result.smtp_verified is False else 'Unknown',
                        'Disposable': 'Yes' if best_result.is_disposable else 'No',
                        'Catch_All': 'Yes' if best_result.is_catch_all else 'No' if best_result.is_catch_all is False else 'Unknown',
                        'Details': '; '.join(best_result.details)
                    })
            
            progress_bar.progress(1.0)
            df = pd.DataFrame(all_results)
            
            found = sum(1 for r in all_results if r.get('SMTP_Verified') == 'Yes')
            
            st.success(f"""
✅ Email Finding Complete!
━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Results: {total_entries} people processed
🎯 Found: {found} verified emails
━━━━━━━━━━━━━━━━━━━━━━━━━━
            """)
            
            st.dataframe(df, use_container_width=True)
            
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name="found_emails_manual.csv",
                mime="text/csv"
            )

with tab4:
    st.markdown("""
### Upload CSV with names and domains to find emails
Choose between:
- **Full Name (one column)**: Name column with "First Last" format
- **Separate Columns**: One column for first name, one for last name

The tool will test **26 different email patterns** for each person!
    """)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        find_csv_file = st.file_uploader("Upload CSV File", type=["csv"], key="find_csv_file")
        
        find_csv_name_mode = st.radio(
            "Name Format",
            ["Full Name (one column)", "Separate Columns (first + last)"],
            index=1,
            key="find_csv_name_mode"
        )
        
        if find_csv_name_mode == "Full Name (one column)":
            find_csv_fullname = st.text_input("Full Name Column", value="name", key="find_csv_fullname")
        else:
            col_a, col_b = st.columns(2)
            with col_a:
                find_csv_first = st.text_input("First Name Column", value="first_name", key="find_csv_first")
            with col_b:
                find_csv_last = st.text_input("Last Name Column", value="last_name", key="find_csv_last")
        
        find_csv_domain = st.text_input("Domain Column", value="domain", key="find_csv_domain")
        
        find_csv_export = st.radio(
            "Export Options",
            ["Full Results", "Valid Only (including catch-all)", "Valid Only (excluding catch-all)", "All Options"],
            key="find_csv_export"
        )
    
    with col2:
        find_csv_delay = st.slider(
            "Delay Between Checks (seconds)",
            min_value=0.5,
            max_value=5.0,
            value=1.0,
            step=0.5,
            key="find_csv_delay"
        )
        find_csv_btn = st.button("🔍 Find Emails", type="primary", key="find_csv_btn")
    
    if find_csv_btn:
        if find_csv_file is None:
            st.error("❌ Please upload a CSV file")
        else:
            try:
                df_input = pd.read_csv(find_csv_file)
                
                if find_csv_name_mode == "Full Name (one column)":
                    if find_csv_fullname not in df_input.columns:
                        available = ', '.join(df_input.columns.tolist())
                        st.error(f"❌ Column '{find_csv_fullname}' not found. Available: {available}")
                        st.stop()
                else:
                    missing = []
                    if find_csv_first not in df_input.columns:
                        missing.append(find_csv_first)
                    if find_csv_last not in df_input.columns:
                        missing.append(find_csv_last)
                    
                    if missing:
                        available = ', '.join(df_input.columns.tolist())
                        st.error(f"❌ Columns not found: {', '.join(missing)}. Available: {available}")
                        st.stop()
                
                if find_csv_domain not in df_input.columns:
                    available = ', '.join(df_input.columns.tolist())
                    st.error(f"❌ Column '{find_csv_domain}' not found. Available: {available}")
                    st.stop()
                
                total = len(df_input)
                results_data = []
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for idx, row in df_input.iterrows():
                    status_text.text(f"Processing {idx+1}/{total}")
                    progress_bar.progress((idx + 1) / total)
                    
                    if find_csv_name_mode == "Full Name (one column)":
                        full_name = str(row[find_csv_fullname]).strip()
                        if not full_name or full_name == 'nan':
                            results_data.append({
                                'Found_Email': 'ERROR',
                                'Pattern': '',
                                'Status': 'INVALID',
                                'Deliverable': 'No',
                                'Confidence': '0%',
                                'SMTP_Verified': 'No',
                                'Disposable': 'No',
                                'Catch_All': 'Unknown',
                                'Details': 'Missing name'
                            })
                            continue
                        
                        name_parts = full_name.split()
                        if len(name_parts) < 2:
                            results_data.append({
                                'Found_Email': 'ERROR',
                                'Pattern': '',
                                'Status': 'INVALID',
                                'Deliverable': 'No',
                                'Confidence': '0%',
                                'SMTP_Verified': 'No',
                                'Disposable': 'No',
                                'Catch_All': 'Unknown',
                                'Details': 'Name must have at least first and last (space-separated)'
                            })
                            continue
                        
                        first_name = name_parts[0]
                        last_name = name_parts[-1]
                    else:
                        first_name = str(row[find_csv_first]).strip()
                        last_name = str(row[find_csv_last]).strip()
                    
                    domain = str(row[find_csv_domain]).strip()
                    
                    if not first_name or not last_name or not domain or first_name == 'nan' or last_name == 'nan' or domain == 'nan':
                        results_data.append({
                            'Found_Email': 'ERROR',
                            'Pattern': '',
                            'Status': 'INVALID',
                            'Deliverable': 'No',
                            'Confidence': '0%',
                            'SMTP_Verified': 'No',
                            'Disposable': 'No',
                            'Catch_All': 'Unknown',
                            'Details': 'Missing name or domain'
                        })
                        continue
                    
                    patterns = verifier.generate_email_patterns(first_name, last_name, domain)
                    
                    found_email = None
                    best_result = None
                    pattern_name = ''
                    
                    for pattern_info in patterns:
                        email = pattern_info['email']
                        pattern_name = pattern_info['pattern']
                        
                        result = verifier.verify(email, check_smtp=True, check_catch_all=True)
                        
                        if result.smtp_verified is True:
                            found_email = email
                            best_result = result
                            break
                        
                        if best_result is None or (result.confidence_score > best_result.confidence_score):
                            found_email = email
                            best_result = result
                        
                        time.sleep(find_csv_delay)
                    
                    if best_result:
                        results_data.append({
                            'Found_Email': found_email,
                            'Pattern': pattern_name,
                            'Status': best_result.status,
                            'Deliverable': 'Yes' if best_result.deliverable else 'No',
                            'Confidence': f"{best_result.confidence_score}%",
                            'SMTP_Verified': 'Yes' if best_result.smtp_verified else 'No' if best_result.smtp_verified is False else 'Unknown',
                            'Disposable': 'Yes' if best_result.is_disposable else 'No',
                            'Catch_All': 'Yes' if best_result.is_catch_all else 'No' if best_result.is_catch_all is False else 'Unknown',
                            'Details': '; '.join(best_result.details)
                        })
                
                results_df = pd.DataFrame(results_data)
                final_df = pd.concat([df_input, results_df], axis=1)
                
                found = sum(1 for r in results_data if r.get('SMTP_Verified') == 'Yes')
                
                st.success(f"""
✅ Email Finding Complete!
━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Results: {total} people processed
🎯 Found: {found} verified emails
━━━━━━━━━━━━━━━━━━━━━━━━━━
                """)
                
                st.dataframe(final_df, use_container_width=True)
                
                csv_full = final_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download Full Results CSV",
                    data=csv_full,
                    file_name="found_emails_full.csv",
                    mime="text/csv",
                    key="download_find_full"
                )
                
                if find_csv_export in ["Valid Only (including catch-all)", "All Options"]:
                    mask = final_df['Status'].isin(['VALID', 'RISKY'])
                    filtered_with = final_df[mask].copy()
                    if len(filtered_with) > 0:
                        csv_with = filtered_with.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="📥 Download Valid (with catch-all) CSV",
                            data=csv_with,
                            file_name="found_emails_valid_with_catchall.csv",
                            mime="text/csv",
                            key="download_find_valid_with"
                        )
                
                if find_csv_export in ["Valid Only (excluding catch-all)", "All Options"]:
                    mask = (final_df['Status'] == 'VALID') & (final_df['Catch_All'] != 'Yes')
                    filtered_no = final_df[mask].copy()
                    if len(filtered_no) > 0:
                        csv_no = filtered_no.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="📥 Download Valid (no catch-all) CSV",
                            data=csv_no,
                            file_name="found_emails_valid_no_catchall.csv",
                            mime="text/csv",
                            key="download_find_valid_no"
                        )
                
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

with tab5:
    st.markdown("""
### 🧹 Email List Cleaning & Deduplication Tools
Clean and prepare your email lists for verification or campaigns.
    """)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        clean_method = st.radio(
            "Input Method",
            ["Manual Input", "CSV Upload"],
            key="clean_method"
        )
        
        if clean_method == "Manual Input":
            clean_manual_input = st.text_area(
                "Email Addresses (one per line or comma-separated)",
                placeholder="user1@gmail.com\nUSER1@Gmail.com\nuser2@yahoo.com\nuser2@yahoo.com",
                height=200,
                key="clean_manual_input"
            )
        else:
            clean_csv_file = st.file_uploader("Upload CSV File", type=["csv"], key="clean_csv_file")
            clean_csv_column = st.text_input("Email Column Name", value="email", key="clean_csv_column")
    
    with col2:
        st.markdown("#### Cleaning Options")
        remove_duplicates = st.checkbox("Remove Duplicates", value=True, key="remove_duplicates")
        normalize_case = st.checkbox("Normalize to Lowercase", value=True, key="normalize_case")
        remove_invalid_syntax = st.checkbox("Remove Invalid Syntax", value=True, key="remove_invalid_syntax")
        remove_disposable = st.checkbox("Remove Disposable Emails", value=False, key="remove_disposable")
        remove_role_based = st.checkbox("Remove Role-based (admin, info, etc.)", value=False, key="remove_role_based")
        
        clean_btn = st.button("🧹 Clean Email List", type="primary", key="clean_btn")
    
    if clean_btn:
        emails_to_clean = []
        
        if clean_method == "Manual Input":
            if not clean_manual_input or not clean_manual_input.strip():
                st.error("❌ Please enter at least one email address")
            else:
                emails_text = clean_manual_input.replace(',', '\n')
                emails_to_clean = [e.strip() for e in emails_text.split('\n') if e.strip()]
        else:
            if clean_csv_file is None:
                st.error("❌ Please upload a CSV file")
            else:
                try:
                    df_clean = pd.read_csv(clean_csv_file)
                    if clean_csv_column not in df_clean.columns:
                        available = ', '.join(df_clean.columns.tolist())
                        st.error(f"❌ Column '{clean_csv_column}' not found. Available: {available}")
                    else:
                        emails_to_clean = df_clean[clean_csv_column].dropna().astype(str).tolist()
                except Exception as e:
                    st.error(f"❌ Error reading CSV: {str(e)}")
        
        if emails_to_clean:
            original_count = len(emails_to_clean)
            cleaned_emails = []
            removed_emails = []
            removal_reasons = {}
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i, email in enumerate(emails_to_clean):
                status_text.text(f"Cleaning {i+1}/{original_count}...")
                progress_bar.progress((i + 1) / original_count)
                
                email_lower = email.strip().lower() if normalize_case else email.strip()
                reason = []
                
                if remove_invalid_syntax:
                    syntax_valid, syntax_msg = verifier.validate_syntax(email_lower)
                    if not syntax_valid:
                        reason.append(f"Invalid syntax: {syntax_msg}")
                        removed_emails.append(email)
                        removal_reasons[email] = '; '.join(reason)
                        continue
                
                if remove_disposable:
                    try:
                        domain = email_lower.split('@')[1]
                        if verifier.is_disposable(domain):
                            reason.append("Disposable email domain")
                            removed_emails.append(email)
                            removal_reasons[email] = '; '.join(reason)
                            continue
                    except:
                        pass
                
                if remove_role_based:
                    if verifier.is_role_based(email_lower):
                        reason.append("Role-based email")
                        removed_emails.append(email)
                        removal_reasons[email] = '; '.join(reason)
                        continue
                
                if remove_duplicates:
                    if email_lower in cleaned_emails:
                        reason.append("Duplicate")
                        removed_emails.append(email)
                        removal_reasons[email] = '; '.join(reason)
                        continue
                
                cleaned_emails.append(email_lower)
            
            progress_bar.progress(1.0)
            
            duplicates_removed = original_count - len(set(emails_to_clean)) if not normalize_case else 0
            final_count = len(cleaned_emails)
            removed_count = len(removed_emails)
            
            st.success(f"""
✅ Email List Cleaned!
━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Original: {original_count} emails
✅ Cleaned: {final_count} emails
❌ Removed: {removed_count} emails
━━━━━━━━━━━━━━━━━━━━━━━━━━
            """)
            
            col_res1, col_res2 = st.columns(2)
            
            with col_res1:
                st.markdown("#### ✅ Cleaned Emails")
                cleaned_df = pd.DataFrame({'Email': cleaned_emails})
                st.dataframe(cleaned_df, use_container_width=True, height=300)
                
                csv_cleaned = cleaned_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download Cleaned List",
                    data=csv_cleaned,
                    file_name="cleaned_emails.csv",
                    mime="text/csv",
                    key="download_cleaned"
                )
            
            with col_res2:
                st.markdown("#### ❌ Removed Emails")
                if removed_emails:
                    removed_df = pd.DataFrame({
                        'Email': removed_emails,
                        'Reason': [removal_reasons.get(e, 'Unknown') for e in removed_emails]
                    })
                    st.dataframe(removed_df, use_container_width=True, height=300)
                    
                    csv_removed = removed_df.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="📥 Download Removed List",
                        data=csv_removed,
                        file_name="removed_emails.csv",
                        mime="text/csv",
                        key="download_removed"
                    )
                else:
                    st.info("No emails were removed")
            
            breakdown = {
                'Invalid Syntax': sum(1 for r in removal_reasons.values() if 'Invalid syntax' in r),
                'Duplicates': sum(1 for r in removal_reasons.values() if 'Duplicate' in r),
                'Disposable': sum(1 for r in removal_reasons.values() if 'Disposable' in r),
                'Role-based': sum(1 for r in removal_reasons.values() if 'Role-based' in r),
            }
            
            st.markdown("#### 📊 Removal Breakdown")
            breakdown_df = pd.DataFrame({
                'Reason': list(breakdown.keys()),
                'Count': list(breakdown.values())
            })
            breakdown_df = breakdown_df[breakdown_df['Count'] > 0]
            if not breakdown_df.empty:
                st.dataframe(breakdown_df, use_container_width=True, hide_index=True)

with tab6:
    st.markdown("### 📊 Verification History & Analytics")
    
    conn = get_db_connection()
    
    if not conn:
        st.error("❌ Database connection not available")
    else:
        col1, col2, col3 = st.columns(3)
        
        try:
            cur = conn.cursor()
            
            cur.execute("SELECT COUNT(*) FROM verification_history")
            total_verified = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM verification_history WHERE status = 'VALID'")
            total_valid = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM verification_history WHERE is_disposable = true")
            total_disposable = cur.fetchone()[0]
            
            with col1:
                st.metric("Total Verified", total_verified)
            
            with col2:
                st.metric("Valid Emails", total_valid, f"{(total_valid/total_verified*100) if total_verified > 0 else 0:.1f}%")
            
            with col3:
                st.metric("Disposable Found", total_disposable)
            
            st.markdown("---")
            
            tab_overview, tab_recent, tab_stats = st.tabs(["📈 Overview", "🕐 Recent Verifications", "📊 Daily Stats"])
            
            with tab_overview:
                cur.execute("""
                    SELECT status, COUNT(*) as count
                    FROM verification_history
                    GROUP BY status
                """)
                status_data = cur.fetchall()
                
                if status_data:
                    status_df = pd.DataFrame(status_data, columns=['Status', 'Count'])
                    fig = px.pie(status_df, values='Count', names='Status', 
                                title='Email Status Distribution',
                                color='Status',
                                color_discrete_map={'VALID': '#28a745', 'INVALID': '#dc3545', 
                                                   'RISKY': '#ffc107', 'UNKNOWN': '#6c757d'})
                    st.plotly_chart(fig, use_container_width=True)
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        cur.execute("""
                            SELECT verification_type, COUNT(*) as count
                            FROM verification_history
                            GROUP BY verification_type
                        """)
                        type_data = cur.fetchall()
                        if type_data:
                            type_df = pd.DataFrame(type_data, columns=['Type', 'Count'])
                            fig2 = px.bar(type_df, x='Type', y='Count', 
                                        title='Verifications by Type')
                            st.plotly_chart(fig2, use_container_width=True)
                    
                    with col2:
                        cur.execute("""
                            SELECT 
                                SUM(CASE WHEN is_disposable THEN 1 ELSE 0 END) as disposable,
                                SUM(CASE WHEN is_role_based THEN 1 ELSE 0 END) as role_based,
                                SUM(CASE WHEN is_free_provider THEN 1 ELSE 0 END) as free_provider
                            FROM verification_history
                        """)
                        flags_data = cur.fetchone()
                        flags_df = pd.DataFrame({
                            'Flag': ['Disposable', 'Role-based', 'Free Provider'],
                            'Count': [flags_data[0], flags_data[1], flags_data[2]]
                        })
                        fig3 = px.bar(flags_df, x='Flag', y='Count', 
                                    title='Email Characteristics')
                        st.plotly_chart(fig3, use_container_width=True)
                else:
                    st.info("No verification data available yet. Start verifying emails to see analytics!")
            
            with tab_recent:
                limit = st.slider("Number of recent records", 10, 100, 50, key="recent_limit")
                
                cur.execute(f"""
                    SELECT email, status, confidence_score, deliverable, 
                           smtp_verified, verified_at, verification_type
                    FROM verification_history
                    ORDER BY verified_at DESC
                    LIMIT {limit}
                """)
                recent_data = cur.fetchall()
                
                if recent_data:
                    recent_df = pd.DataFrame(recent_data, columns=[
                        'Email', 'Status', 'Confidence', 'Deliverable', 
                        'SMTP Verified', 'Verified At', 'Type'
                    ])
                    st.dataframe(recent_df, use_container_width=True)
                    
                    csv_recent = recent_df.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="📥 Download Recent History",
                        data=csv_recent,
                        file_name="recent_verification_history.csv",
                        mime="text/csv"
                    )
                else:
                    st.info("No verification history yet")
            
            with tab_stats:
                cur.execute("""
                    SELECT date, total_verifications, valid_count, 
                           invalid_count, risky_count
                    FROM verification_stats
                    ORDER BY date DESC
                    LIMIT 30
                """)
                stats_data = cur.fetchall()
                
                if stats_data:
                    stats_df = pd.DataFrame(stats_data, columns=[
                        'Date', 'Total', 'Valid', 'Invalid', 'Risky'
                    ])
                    
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(x=stats_df['Date'], y=stats_df['Total'], 
                                           mode='lines+markers', name='Total',
                                           line=dict(color='#007bff', width=2)))
                    fig.add_trace(go.Scatter(x=stats_df['Date'], y=stats_df['Valid'], 
                                           mode='lines+markers', name='Valid',
                                           line=dict(color='#28a745', width=2)))
                    fig.add_trace(go.Scatter(x=stats_df['Date'], y=stats_df['Invalid'], 
                                           mode='lines+markers', name='Invalid',
                                           line=dict(color='#dc3545', width=2)))
                    
                    fig.update_layout(
                        title='Daily Verification Trends (Last 30 Days)',
                        xaxis_title='Date',
                        yaxis_title='Count',
                        hovermode='x unified'
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                    
                    st.dataframe(stats_df, use_container_width=True)
                else:
                    st.info("No daily stats available yet")
            
            cur.close()
            conn.close()
            
        except Exception as e:
            st.error(f"Error loading analytics: {str(e)}")
            if conn:
                conn.close()

st.markdown("---")
st.markdown("""
### 📋 Email Patterns Tested (26 total):
`firstlast@`, `lastfirst@`, `first_last@`, `last_first@`, `first.last@`, `last.first@`, 
`first-last@`, `last-first@`, `flast@`, `firstl@`, `lfirst@`, `lastf@`, `first@`, `last@`,
`f.last@`, `first.l@`, `last.f@`, `l.first@`, `first_l@`, `last_f@`, `f_last@`, `l_first@`,
`l-first@`, `f-last@`, `first-l@`, `last-f@`

### 📊 Export Options:
- **Full Results**: Complete CSV with all verification data
- **Valid Only (including catch-all)**: Only VALID + RISKY (catch-all) rows
- **Valid Only (excluding catch-all)**: Only VALID rows (no catch-all domains)
- **All Options**: Get all 3 CSV files at once

### 📊 Result Columns:
- **Status**: VALID ✅ / INVALID ❌ / RISKY ⚠️ / UNKNOWN ❓
- **Deliverable**: Can you send emails to this address?
- **Confidence**: 0-100% confidence score (higher is better)
- **SMTP_Verified**: Mailbox verified via SMTP server
- **Pattern**: Which email format was found (for Find Email mode)
- **Catch_All**: Domain accepts all emails (can't verify specific mailbox)

### 💡 Tips:
- **Verify Mode**: Check if existing emails are valid
- **Find Mode**: Discover email addresses from names + domains
- Use 1-2 second delay to avoid rate limiting
- Finding emails tests 26 patterns so it takes longer
- **Name Format Options**:
  - "John Doe" in one column → Use "Full Name (one column)"
  - "John" and "Doe" in separate columns → Use "Separate Columns"
- **Export filtered CSVs** to clean your lists automatically

### ⚡ Performance:
- Verification: ~2-3 seconds per email
- Finding: ~30-60 seconds per person (tests 26 patterns)
- Use delays to prevent server blocks

### ⚠️ Important Note:
SMTP verification on port 25 may be limited on cloud hosting platforms. The tool will attempt SMTP verification and gracefully handle any connection restrictions. All other verification methods (syntax, DNS, MX records, disposable detection) will work perfectly.
""")
