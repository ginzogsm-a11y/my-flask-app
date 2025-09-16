# 🛠️ مشروع Ginzogsm

تطبيق ويب مبني باستخدام **Flask** لإدارة المستخدمين مع ميزات التسجيل، تسجيل الدخول، تفعيل الحسابات، وإدارة لوحة تحكم المسؤول.  
مُجهّز للعمل على **Render** مع دعم قاعدة بيانات MySQL.

---

## 🚀 المميزات
- تسجيل مستخدمين جدد مع تخزين بيانات (اسم مستخدم، بريد إلكتروني، هاتف).
- تسجيل الدخول مع خيار "تذكرني".
- حماية بكلمة مرور مشفّرة (bcrypt).
- إمكانية إعادة تعيين كلمة المرور (Token).
- إدارة الأجهزة المستخدمة من قِبل المستخدم.
- واجهة **مسؤول** لتفعيل/حذف المستخدمين.
- قوالب HTML جاهزة (Bootstrap مبسّط).
- مُهيأ للنشر على **Render**.

---

## 📂 هيكل المشروع

```
ginzogsm/
│── app.py                # التطبيق الرئيسي
│── wsgi.py               # نقطة الدخول للنشر (Gunicorn)
│── create_admin.py       # سكربت لإنشاء حساب مسؤول
│── test_db.py            # اختبار اتصال قاعدة البيانات
│── requirements.txt      # المكتبات المطلوبة
│── Procfile              # تعريف أمر التشغيل لـ Render
│── .env.example          # نموذج لملف المتغيرات السرية
│── README.md             # هذا الملف
│
├── templates/            # قوالب HTML
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── account.html
│   ├── admin.html
│   ├── reset_request.html
│   ├── reset_token.html
│   └── error.html
│
├── static/               # ملفات CSS/JS
│   └── style.css
│
└── screenshots/          # لقطات شاشة للتوثيق
    ├── login.png
    ├── register.png
    └── admin.png
```

---

## ⚙️ الإعداد المحلي

1. **نسخ المشروع:**
   ```bash
   git clone https://github.com/username/ginzogsm.git
   cd ginzogsm
   ```

2. **إنشاء بيئة افتراضية وتثبيت المتطلبات:**
   ```bash
   python -m venv venv
   source venv/bin/activate   # على Linux / Mac
   venv\Scripts\activate      # على Windows
   pip install -r requirements.txt
   ```

3. **إعداد ملف البيئة:**
   انسخ `.env.example` إلى `.env` ثم عدّل القيم:
   ```ini
   SECRET_KEY=your-secret-key
   DB_USER=your-db-user
   DB_PASSWORD=your-db-password
   DB_HOST=your-db-host
   DB_NAME=your-db-name
   ```

4. **تهيئة قاعدة البيانات:**
   ```bash
   python app.py
   ```

5. **تشغيل التطبيق محلياً:**
   ```bash
   flask run
   ```
   ثم افتح [http://localhost:5000](http://localhost:5000).

---

## ☁️ النشر على Render

1. اربط مستودع GitHub مع حسابك في [Render](https://render.com).
2. أنشئ خدمة جديدة **Web Service**.
3. اختر إعدادات التشغيل:
   - **Environment:** Python 3
   - **Start Command:**
     ```bash
     gunicorn wsgi:app
     ```
4. أضف المتغيرات البيئية من `.env`.
5. اربط التطبيق بقاعدة بيانات MySQL (يمكن استخدام MySQL على Render أو خارجي مثل ClearDB).

---

## 👤 إنشاء حساب مسؤول

لتفعيل لوحة التحكم، تحتاج إلى حساب **Admin**:  
```bash
python create_admin.py
```

---

## 🧪 اختبار قاعدة البيانات

```bash
python test_db.py
```

---

## 🖼️ لقطات الشاشة

### صفحة تسجيل الدخول
![Login](screenshots/login.png)

---

### صفحة التسجيل
![Register](screenshots/register.png)

---

### لوحة تحكم المسؤول
![Admin Panel](screenshots/admin.png)

---

## 📜 الرخصة

المشروع مفتوح المصدر – يمكنك التعديل والاستخدام بحرية.
"# my-flask-app" 
