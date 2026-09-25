# Nisha Seva Foundation — Backend + Admin Panel

Yeh ek Node.js (Express) backend hai jo website ko dynamic banata hai.
Koi alag database install nahi karni — data ek JSON file (`data/db.json`) me store hota hai.

## Kya milta hai

- Public API: `/api/programs`, `/api/events`, `/api/gallery`, `/api/documents`, `/api/donors`
- Form submissions receive karne ke liye: `/api/volunteers`, `/api/members`, `/api/contactMessages`, `/api/newsletter`
- Admin panel: `/admin` — login karke Programs, Events, Gallery, Documents, Donors add/edit/delete kar sakte hain, aur Volunteer/Member/Contact submissions dekh sakte hain.

## Local par chalane ke liye (Node.js installed hona chahiye)

```bash
cd nisha-backend
cp .env.example .env
# .env file kholkar ADMIN_USERNAME aur ADMIN_PASSWORD apni pasand ka set karein
npm install
npm start
```

Server `http://localhost:4000` par chalega.
Admin panel: `http://localhost:4000/admin`

## Hosting par deploy karne ke liye

Yeh ek Node.js app hai, isliye hosting me **Node.js support** hona chahiye
(jaise Render, Railway, Hostinger ka Node hosting, ya koi VPS/cPanel jisme Node app run ho sake).
Plain shared PHP-only hosting is par kaam nahi karega.

Steps (general — hosting provider ke hisaab se thoda alag ho sakta hai):

1. Poora `nisha-backend` folder hosting par upload karein.
2. Environment variables set karein: `PORT`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`.
3. `npm install` chalayein.
4. `npm start` (ya hosting ka "Start command" `node server.js` set karein).
5. Aapko ek live URL milega, jaise `https://api.nishasevafoundation.org`.

## Website ko dynamic banana (agla step)

Jab yeh backend live ho jaye, mujhe uska live API URL bhej dein —
main website ke Programs, Events, Gallery, Donors, Documents sections ko
static data ki jagah is API se fetch karne wala bana dunga, aur
Volunteer / Member Apply / Contact forms ko is backend par submit hone wala bana dunga.

## Documents / Gallery images upload karna

Admin panel se abhi file-upload button nahi hai (link-based hai) —
`POST /api/upload` endpoint ready hai (multer se), agar chahein to main
admin panel me seedha file-upload button bhi jod sakta hoon.
