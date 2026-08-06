DLM WALLET AUTH BACKEND

Sa pake sa a fè:
- Kreye kont kliyan nan PostgreSQL.
- Chifre modpas ak bcryptjs.
- Login ak JWT.
- Wòl customer/admin.
- fastpayhaiti@gmail.com vin admin otomatikman.
- Chak kliyan gen pwòp balans pa li.
- Sèl admin ka ajiste balans kliyan.

ENPÒTAN:
1. Mete fichye backend yo nan sèvis Render backend ou a.
2. Kreye yon PostgreSQL database.
3. Egzekite schema.sql nan database la.
4. Mete environment variables ki nan .env.example sou Render.
5. Nan public-js/auth-api.js, ranplase:
   https://YOUR-RENDER-SERVICE.onrender.com
   ak URL backend Render pa ou.
6. Mete auth-api.js nan repo frontend GitHub la.
7. Login/register HTML yo dwe rele fonksyon loginDlmUser ak registerDlmUser.

Pa mete DATABASE_URL oswa JWT_SECRET nan GitHub piblik.
Pa mete modpas admin nan kòd la.
