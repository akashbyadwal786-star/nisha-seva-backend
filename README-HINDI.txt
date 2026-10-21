NISHA SEVA FOUNDATION — HOSTINGER MYSQL MIGRATION STARTER

स्थिति: यह staging starter है, production-ready प्रमाणित पैकेज नहीं। वास्तविक Hostinger database पर परीक्षण जरूरी है।

लक्ष्य
- Frontend: https://nishasevafoundation.org
- Backend API: https://api.nishasevafoundation.org (Hostinger Node.js Web App से इस subdomain को जोड़ना होगा)
- Database: Hostinger MySQL
- Image uploads: backend की persistent uploads/ directory

पैकेज में
- server.js: Supabase SDK के बिना backend draft; image upload local uploads/ में करता है।
- db.js: mysql2 driver और legacy PostgreSQL-style queries के लिए compatibility adapter। यह adapter सभी queries की सही execution की गारंटी नहीं देता।
- package.json: Node.js dependencies
- .env.example: environment variable नाम, कोई secret नहीं
- schema.sql: app_data table का reference schema; पहले से मौजूद table पर इसे लागू करने से पहले structure verify करें।

पहले ये काम करें
1. Render और Supabase को अभी बंद/डिलीट न करें।
2. Hostinger phpMyAdmin में app_data का Export/Backup लें। मौजूदा table/records न हटाएँ।
3. Hostinger Node.js Web App बनाएँ और api.nishasevafoundation.org को उसी app से जोड़ें। केवल public_html में GitHub deploy करने से Express backend अपने-आप नहीं चलता।
4. Backend repository में server.js, db.js, package.json, .env.example और uploads/ directory रखें। वास्तविक .env या passwords GitHub में न डालें।
5. Hostinger Node.js app के Environment Variables में DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, ADMIN_USERNAME, ADMIN_PASSWORD और PUBLIC_BASE_URL सेट करें। PUBLIC_BASE_URL=https://api.nishasevafoundation.org रखें।
6. Node app के logs में MySQL connection और startup errors जाँचें। इस draft में DB connection startup पर पूरी तरह health-check नहीं होता, इसलिए /api route को test करें।
7. Frontend और Admin HTML में API base URL को https://api.nishasevafoundation.org पर बदलें। अगर किसी page में API_BASE या API variable Render URL पर है, उसे बदलना जरूरी है।
8. Login, programs/events/gallery load, donor list, volunteer/member forms, newsletter, internship approve/reject, project submissions, verification links और image upload सब जाँचें।
9. Gallery के पुराने image URLs अभी Supabase Storage पर हो सकते हैं। उन्हें Hostinger uploads/ में copy करके records में URL update करें। जब तक सब images और records verify न हों, Supabase delete न करें।
10. सब tests pass होने और backup verify होने के बाद ही Render/Supabase dependencies हटाएँ।

महत्वपूर्ण सीमाएँ
- Existing app_data JSON record को overwrite न करें। db.js readDB/writeDB उसी id=1 row को पढ़ता/अपडेट करता है। पहले पुष्टि करें कि imported row id=1 है और data JSON वैध है।
- db.js SQL compatibility adapter $1 placeholders, JSONB, RETURNING आदि को MySQL में translate करता है। Complex UPDATE/DELETE/RETURNING paths को staging पर जाँचना आवश्यक है।
- Internship/project submission tables के लिए code CREATE TABLE IF NOT EXISTS चलाता है; production पर चलाने से पहले schema backup और test करें।
- Local uploads तभी सुरक्षित हैं जब Hostinger app का filesystem persistent हो और deployment के दौरान uploads directory न मिटे। यदि hosting पर app directory redeploy के समय reset होती है, persistent storage विकल्प चाहिए।
- इस पैकेज से कोई live migration, database import या hosting change अपने-आप नहीं हुआ है।
