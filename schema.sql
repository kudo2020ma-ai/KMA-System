-- ============================================================
-- نظام إدارة مشاريع المقاولات v2 — مخطط قاعدة البيانات المشتركة
-- (Vercel Postgres) — خدمة mshry-shared-db
-- ============================================================
-- تنبيه: الجدول mshry_records موجود أصلاً في قاعدة Neon
-- وهو فارغ حالياً (0 صفوف) بعد المسح. هذا الملف يُنفَّذ مرة
-- واحدة لإضافة فهرس التفرد الجزئي الجديد على اسم المستخدم
-- (لا يعيد إنشاء الجدول ولا يمسّ أي بيانات).
-- لا تمسّ جدول kma_records إطلاقًا — لا قراءة ولا كتابة
-- ولا حذف ولا تعديل؛ بيانات KMA تبقى سليمة تماماً.
-- ============================================================

-- جدول واحد عام يحفظ كل مجموعات النظام (مشاريع، عملاء، فنّيون،
-- تكليفات، تقارير موقع، عروض أسعار، عقود، مواد، دفعات،
-- مستخدمون، إعدادات...).
-- العزل بين الشركات يتم عبر company_id.
CREATE TABLE IF NOT EXISTS mshry_records (
  company_id TEXT NOT NULL,
  collection TEXT NOT NULL,
  id TEXT NOT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (company_id, collection, id)
);

-- فهرس لتسريع قراءة مجموعة كاملة لشركة واحدة
-- (أكثر عملية قراءة شيوعاً: GET /api/data?collection=X).
CREATE INDEX IF NOT EXISTS idx_mshry_records_company_collection
  ON mshry_records (company_id, collection);

-- فهرس على وقت التحديث لترتيب السجلات الأحدث أولاً.
CREATE INDEX IF NOT EXISTS idx_mshry_records_updated_at
  ON mshry_records (updated_at DESC);

-- فهرس تفرد جزئي جديد (v2 — §16.3 من وثيقة التصميم):
-- يمنع تكرار اسم المستخدم داخل مجموعة users حتى لو اختلف الدور
-- أو المعرّف، فيمنع بالبنية دخول مستخدم بدور خاطئ بسبب اسم مكرر.
-- جزئي (WHERE collection = 'users') فلا يؤثر على باقي المجموعات.
CREATE UNIQUE INDEX IF NOT EXISTS idx_mshry_users_username
  ON mshry_records ((data->>'username'))
  WHERE collection = 'users';
