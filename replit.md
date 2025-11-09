# Email Verification & Finder Tool

## Overview
Professional email verification tool with SMTP validation, bulk processing, deduplication, and analytics dashboard. Migrated from Gradio to Streamlit for deployment on Replit.

## Core Features

### 1. Email Verification
- **Manual Input**: Verify emails one-by-one or in batches via text input
- **CSV Upload**: Upload CSV files for bulk email verification
- **Concurrent Processing**: Use ThreadPoolExecutor to verify multiple emails in parallel (5-10 workers)
- **Comprehensive Validation**:
  - Syntax validation (RFC 5322 compliance)
  - Domain existence check (DNS lookup)
  - MX record retrieval and validation
  - SMTP verification (port 25, with graceful fallback)
  - Disposable email detection
  - Role-based email detection (admin, info, support, etc.)
  - Free provider identification (Gmail, Yahoo, Outlook, etc.)
  - Catch-all domain detection
  - Confidence scoring system (0-100)

### 2. Email Finding
- **Pattern Generation**: Tests 26 different email patterns for name + domain combinations
- **Manual Mode**: Enter FirstName LastName domain.com format
- **CSV Mode**: Upload CSV with name columns and domain column
- **Smart Detection**: Stops when valid email is found or tests all patterns

### 3. Email List Cleaning & Deduplication
- **Deduplication**: Remove duplicate emails (case-insensitive)
- **Normalization**: Convert all emails to lowercase
- **Syntax Filtering**: Remove emails with invalid syntax
- **Disposable Filtering**: Remove temporary/disposable email addresses
- **Role-based Filtering**: Remove role-based emails (admin, info, etc.)
- **Results Display**: Shows cleaned list and removed list with reasons

### 4. Verification History & Analytics
- **PostgreSQL Storage**: All verifications saved to database with batch tracking
- **Summary Metrics**: Total verified, valid emails, disposable found
- **Visual Analytics**:
  - Pie chart: Email status distribution
  - Bar charts: Verifications by type, email characteristics
  - Line chart: Daily verification trends (30 days)
- **Recent History**: View and download recent verification records
- **Daily Statistics**: Aggregated daily stats with trend analysis

## Database Schema

### verification_history
Stores individual verification results:
- `id`: Serial primary key
- `email`: Email address (varchar 255)
- `status`: VALID, INVALID, RISKY, UNKNOWN
- `syntax_valid`, `domain_exists`, `mx_records_exist`: Boolean flags
- `smtp_verified`, `is_catch_all`: Nullable booleans
- `is_disposable`, `is_role_based`, `is_free_provider`: Boolean flags
- `confidence_score`: Integer (0-100)
- `deliverable`: Boolean
- `details`: Text (semicolon-separated)
- `verified_at`: Timestamp (default: CURRENT_TIMESTAMP)
- `batch_id`: Varchar (100) for grouping
- `verification_type`: Varchar (50) - 'manual', 'csv', or 'find'

### verification_stats
Stores aggregated daily statistics:
- `id`: Serial primary key
- `date`: Date (unique)
- `total_verifications`, `valid_count`, `invalid_count`, `risky_count`: Integer counts
- `disposable_count`, `role_based_count`: Integer counts
- `created_at`, `updated_at`: Timestamps

## Technical Stack
- **Frontend**: Streamlit
- **Backend**: Python 3.11
- **Database**: PostgreSQL (Neon-backed)
- **DNS**: dnspython
- **Data**: pandas, openpyxl
- **Visualization**: plotly
- **Concurrency**: ThreadPoolExecutor (concurrent.futures)

## Configuration
- **Port**: 5000 (webview)
- **Database**: Uses DATABASE_URL environment variable
- **Workflow**: `streamlit run app.py --server.port 5000`

## Performance
- **Sequential**: ~2-3 seconds per email
- **Concurrent**: 5-10x faster with 5 workers
- **Email Finding**: ~30-60 seconds per person (tests 26 patterns)

## Important Notes
- SMTP verification on port 25 may be limited on cloud platforms (Replit blocks outbound port 25)
- Tool handles connection restrictions gracefully
- All other verification methods work perfectly (syntax, DNS, MX records, etc.)
- Database saving is optional via checkbox (default: enabled)

## Next Phase Features (Pending)
- API key integration for enhanced SMTP verification services (ZeroBounce, NeverBounce)
- Webhook integration for real-time verification notifications

## User Preferences
- User migrated from Gradio (Google Colab) to Streamlit (Replit)
- Wanted all original features preserved with deployment capability
- Requested concurrent processing for faster bulk operations
- Needed deduplication and cleaning tools
- Wanted verification history and analytics dashboard
