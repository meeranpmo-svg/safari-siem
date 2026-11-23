# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Arabic for every PDPL finding and recurring duty: title and recommendation.

The rules (pdpl_rules, pdpl_workflows, pdpl_ropa, pdpl_catalog, pdpl_access) write their findings in English. This catalogue
recognises each finding by its stable KEY, lifts the variable parts (activity name, reference, categories, counts) from the
English title, and writes the Arabic. tests/pdpl-ar.test.js runs the rules over a synthetic register that raises every finding
type and fails if any comes back without Arabic, so a new finding cannot ship English-only.

  translate(finding) -> {'title_ar', 'recommendation_ar'} | {}   ({} = no Arabic: the caller keeps the English)
"""
import re

CAT_AR = {'identity': 'بيانات الهوية', 'contact': 'بيانات الاتصال', 'financial': 'البيانات المالية', 'health': 'البيانات الصحية', 'credit': 'البيانات الائتمانية',
          'biometric': 'البيانات الحيوية', 'genetic': 'البيانات الوراثية', 'criminal': 'السوابق الجنائية والأمنية', 'religious': 'المعتقد الديني',
          'beliefs': 'المعتقدات الفكرية أو السياسية', 'ethnic': 'الأصل العرقي أو الإثني', 'parentage': 'مجهولية الأبوين', 'location': 'بيانات الموقع',
          'employment': 'البيانات الوظيفية', 'other': 'بيانات أخرى'}
REG_AR = {'Insurance Authority': 'هيئة التأمين', 'Saudi Central Bank (SAMA)': 'البنك المركزي السعودي (ساما)', 'National Cybersecurity Authority (NCA)': 'الهيئة الوطنية للأمن السيبراني',
          'Council of Health Insurance (CHI)': 'مجلس الضمان الصحي', 'Other authority': 'جهة أخرى'}
EXC_AR = {'sensitive record opened with no purpose': 'فتح سجل حساس دون غرض', 'purpose "other" with no reason': 'غرض "أخرى" دون سبب',
          'fraud investigation with no case reference': 'تحقيق احتيال دون رقم قضية', 'sensitive record exported or printed': 'تصدير سجل حساس أو طباعته', 'record deleted': 'حذف سجل'}
DSR_AR = {'access': 'وصول', 'copy': 'نسخة', 'correction': 'تصحيح', 'destruction': 'إتلاف', 'withdraw_consent': 'سحب موافقة', 'objection': 'اعتراض', 'other': 'أخرى'}
EXPOSE_AR = {'shared by an anonymous link (anyone with the link)': 'مشارَك برابط مفتوح لأي شخص', 'shared with people outside the organisation': 'مشارَك مع أشخاص من خارج الشركة',
             'readable by everyone on the file share': 'متاح للقراءة لجميع مستخدمي مجلد المشاركة'}


def cats(s):
    return '، '.join(CAT_AR.get(c.strip(), c.strip()) for c in str(s).split(',') if c.strip())


def _q(name):
    return '«' + str(name) + '»'


# (key pattern, title pattern, Arabic title from the match, Arabic recommendation)
T = [
    (r'^P-01:dpo$', r'', lambda m: 'لم يُسجَّل تعيين مسؤول حماية البيانات', 'عيِّن مسؤول حماية البيانات (داخلياً أو خارجياً)، وسجِّل قرار التعيين وانشر وسيلة التواصل معه.'),
    (r'^P-02:register$', r'', lambda m: 'لم يُسجَّل التسجيل في المنصة الوطنية لحوكمة البيانات (سدايا)', 'سجِّل الشركة بصفتها جهة تحكم (شركة تأمين تعالج بيانات صحية مشمولة بالتسجيل) ودوِّن رقم التسجيل.'),
    (r'^P-03:policy$', r'', lambda m: 'سياسة الخصوصية غير منشورة', 'انشر سياسة الخصوصية المعتمدة في كل موضع تُجمع فيه البيانات (البوابة، التطبيق، النماذج).'),
    (r'^P-04:ropa:.+:incomplete$', r'^Processing activity "(?P<n>.*)" is incomplete$', lambda m: 'نشاط المعالجة ' + _q(m['n']) + ' غير مكتمل', 'أكمل السجل: الغرض، الأساس النظامي، فئات البيانات، مدة الاحتفاظ، المالك.'),
    (r'^P-04:ropa:.+:review$', r'^Processing activity "(?P<n>.*)" not reviewed', lambda m: 'لم يُراجَع نشاط المعالجة ' + _q(m['n']) + ' خلال آخر 12 شهراً', 'راجع السجل مع مالكه وحدِّث تاريخ المراجعة.'),
    (r'^P-05:basis:.+:records$', r'^"(?P<n>.*)" relies on consent', lambda m: 'النشاط ' + _q(m['n']) + ' يعتمد على الموافقة دون سجلات موافقة', 'احتفظ بسجل يُثبت كل موافقة (الوقت، الطريقة، الغرض).'),
    (r'^P-05:basis:.+:explicit$', r'^"(?P<n>.*)" needs explicit consent \((?P<w>.*)\)$', lambda m: 'النشاط ' + _q(m['n']) + ' يحتاج إلى موافقة صريحة (' + (cats(m['w']) if m['w'] != 'solely automated decision' else 'قرار آلي بالكامل') + ')', 'احصل على موافقة صريحة، أو سجِّل أساساً نظامياً آخر.'),
    (r'^P-06:lia:.+:sensitive$', r'^"(?P<n>.*)" uses legitimate interest for sensitive data \((?P<c>.*)\)$', lambda m: 'النشاط ' + _q(m['n']) + ' يستند إلى المصلحة المشروعة لمعالجة بيانات حساسة (' + cats(m['c']) + ')', 'لا تغطي المصلحة المشروعة البيانات الحساسة: انتقل إلى أساس نظامي آخر أو أوقف المعالجة.'),
    (r'^P-15:lia:.+:credit$', r'^"(?P<n>.*)" uses legitimate interest for credit data$', lambda m: 'النشاط ' + _q(m['n']) + ' يستند إلى المصلحة المشروعة لمعالجة بيانات ائتمانية', 'تحتاج البيانات الائتمانية إلى موافقة صريحة من صاحبها (اللائحة التنفيذية، المادتان 11 و27): احصل عليها أو سجِّل أساساً آخر يجيزه النظام.'),
    (r'^P-06:lia:.+:assessment$', r'^"(?P<n>.*)" on legitimate interest', lambda m: 'النشاط ' + _q(m['n']) + ' يستند إلى المصلحة المشروعة دون تقييم مكتوب', 'أكمل تقييم المصلحة المشروعة وسجِّله قبل بدء المعالجة.'),
    (r'^P-07:dpia:', r'^No impact assessment for "(?P<n>.*)"$', lambda m: 'لا يوجد تقييم أثر للنشاط ' + _q(m['n']), 'أكمل تقييم الأثر وسجِّل نتيجته قبل المعالجة (أو بالتزامن معها).'),
    (r'^P-08:dsr:.+:extension$', r'^Request (?P<r>.*) extended without notice', lambda m: 'مُدِّد الطلب ' + m['r'] + ' دون إشعار صاحب البيانات', 'أبلغ صاحب البيانات بالتمديد وأسبابه قبل انتهاء الثلاثين يوماً الأولى.'),
    (r'^P-08:dsr:.+:late$', r'^Request (?P<r>.*) \((?P<t>.*)\) (?P<s>answered|open) after (?P<d>\d+) days$', lambda m: 'الطلب ' + m['r'] + ' (' + DSR_AR.get(m['t'], m['t']) + ') ' + ('أُجيب بعد ' if m['s'] == 'answered' else 'ما زال مفتوحاً بعد ') + m['d'] + ' يوماً', 'أجب عن الطلب، وراجع إجراءات الطلبات حتى تصدر الإجابات خلال 30 يوماً.'),
    (r'^P-09:breach:.+:sdaia$', r'^Breach (?P<r>.*): SDAIA (?:notified after (?P<a>\d+) h|not notified \((?P<b>\d+) h since awareness\))$', lambda m: 'حادثة التسرّب ' + m['r'] + ': ' + ('أُبلغت سدايا بعد ' + m['a'] + ' ساعة' if m['a'] else 'لم تُبلَّغ سدايا (' + m['b'] + ' ساعة منذ العلم بالحادثة)'), 'أبلغ سدايا فوراً بما هو معلوم مع سبب التأخير، وراجع إجراءات الاستجابة للتسرّب.'),
    (r'^P-09:breach:.+:subjects$', r'^Breach (?P<r>.*): data subjects not notified$', lambda m: 'حادثة التسرّب ' + m['r'] + ': لم يُبلَّغ أصحاب البيانات', 'أبلغ أصحاب البيانات بلغة واضحة مع ما عليهم فعله لحماية أنفسهم.'),
    (r'^breach:.+:reg:undecided$', r'^Breach (?P<r>.*): no decision recorded on notifying (?P<l>.*)$', lambda m: 'حادثة التسرّب ' + m['r'] + ': لم يُسجَّل قرار بشأن إبلاغ ' + '، '.join(REG_AR.get(x.strip(), x.strip()) for x in m['l'].split(', ')), 'سجِّل لكل جهة رقابية هل تقتضي تعليماتها الإبلاغ (وأبلغها)، أو سبب عدم الاقتضاء.'),
    (r'^breach:.+:reg:', r'^Breach (?P<r>.*): (?P<l>.*) not notified - its (?P<h>\d+)-hour deadline has passed$', lambda m: 'حادثة التسرّب ' + m['r'] + ': لم تُبلَّغ ' + REG_AR.get(m['l'], m['l']) + ' وقد انقضت المهلة (' + m['h'] + ' ساعة)', 'أبلغ الجهة الآن بما هو معلوم، وسجِّل رقم البلاغ، ووضِّح سبب التأخير.'),
    (r'^P-10:proc:.+:agreement$', r'^Processor (?P<n>.*) has no written agreement$', lambda m: 'معالج البيانات ' + _q(m['n']) + ' دون اتفاقية مكتوبة', 'وقِّع اتفاقية معالجة بيانات تتضمن البنود المطلوبة.'),
    (r'^P-10:proc:.+:clauses$', r'^Processor (?P<n>.*): agreement lacks (?P<c>.*)$', lambda m: 'معالج البيانات ' + _q(m['n']) + ': تنقص الاتفاقية بنوداً (' + m['c'] + ')', 'أضف البنود الناقصة إلى الاتفاقية.'),
    (r'^P-10:proc:.+:assessed$', r'^Processor (?P<n>.*) not assessed', lambda m: 'لم يُقيَّم معالج البيانات ' + _q(m['n']) + ' خلال آخر 12 شهراً', 'قيِّم التزام المعالج (أو كلِّف جهة مستقلة بذلك).'),
    (r'^proc:.+:dd$', r'^Processor (?P<n>.*): due diligence (?P<s>\d+)%$', lambda m: 'معالج البيانات ' + _q(m['n']) + ': نتيجة العناية الواجبة ' + m['s'] + '%', 'عالج الثغرات مع المعالج أو استبدله.'),
    (r'^P-11:transfer:unrecorded$', r'', lambda m: 'تخرج بيانات إلى خارج المملكة دون تسجيل أي نقل', 'سجِّل كل عملية نقل مع أساسها النظامي وتقييم مخاطرها، أو أعِد البيانات إلى المملكة.'),
    (r'^P-11:transfer:.+:reinsurance$', r'^"(?P<n>.*)" is reinsured outside', lambda m: 'النشاط ' + _q(m['n']) + ' مُعاد تأمينه خارج المملكة دون تسجيل نقل لإعادة التأمين', 'سجِّل النقل إلى كل معيد تأمين (الدولة، الأساس، شكل البيانات: مجمّعة أو مستعارة الهوية أو معرِّفة) وتقييم مخاطره.'),
    (r'^P-11:transfer:.+:minimise$', r'^Transfer (?P<n>.*) sends identified sensitive data', lambda m: 'النقل ' + _q(m['n']) + ' يرسل بيانات حساسة معرِّفة إلى معيد التأمين', 'أرسل كشوفاً مجمّعة أو مستعارة الهوية متى أجازت الاتفاقية ذلك، وإلا فسجِّل سبب الحاجة إلى البيانات المعرِّفة.'),
    (r'^P-11:transfer:.+:basis$', r'^Transfer (?P<n>.*) to (?P<c>.*) has no basis$', lambda m: 'النقل ' + _q(m['n']) + ' إلى ' + m['c'] + ' دون أساس نظامي', 'سجِّل الأساس: قرار ملاءمة، أو ضمانات مناسبة (قواعد ملزمة / بنود تعاقدية معيارية / شهادة / مدونة سلوك)، أو استثناء.'),
    (r'^P-11:transfer:.+:risk$', r'^Transfer (?P<n>.*) needs a risk assessment$', lambda m: 'النقل ' + _q(m['n']) + ' يحتاج إلى تقييم مخاطر', 'أكمل تقييم مخاطر النقل قبل التنفيذ.'),
    (r'^P-20:withdrawal:', r'^"(?P<n>.*)" relies on consent but', lambda m: 'النشاط ' + _q(m['n']) + ' يعتمد على الموافقة لكن سحبها لا يُتابَع في سجل الموافقات', 'أضف غرض موافقة لهذا النشاط واجعل النظام الجامع يرسل الموافقات وحالات السحب إلى السجل (وتحقق منه قبل المعالجة).'),
    (r'^P-12:retention:hold:.+:review$', r'^Legal hold (?P<r>.*) has not been reviewed since (?P<d>.*)$', lambda m: 'لم يُراجَع الحجز النظامي ' + m['r'] + ' منذ ' + m['d'], 'تأكد أن المطالبة أو القضية أو الاستفسار ما زال يحتاج السجلات (سجِّل مراجعة)، أو ارفع الحجز ليعود جدول الاحتفاظ ساريًا.'),
    (r'^P-12:retention:.+:schedule$', r'^"(?P<n>.*)" has a retention period but', lambda m: 'النشاط ' + _q(m['n']) + ' له مدة احتفاظ دون قاعدة في جدول الاحتفاظ', 'أضف قاعدة احتفاظ (الأنظمة، الحدث المُطلِق، المدة، المرجع النظامي، إتلاف أو إخفاء هوية) ليُخطَّط للإتلاف ويُوثَّق.'),
    (r'^P-12:retention:.+:overdue$', r'^Retention rule "(?P<n>.*)": no destruction evidenced since (?P<d>.*)$', lambda m: 'قاعدة الاحتفاظ ' + _q(m['n']) + ': لا دليل على إتلاف منذ ' + m['d'], 'خطِّط دورة الإتلاف للسجلات التي انقضت مدتها، واعتمدها من مسؤول حماية البيانات، ونفِّذها ووثِّق الدليل.'),
    (r'^P-12:retention:.+:unapproved$', r'^Destruction (?P<r>\S+) executed', lambda m: 'نُفِّذ الإتلاف ' + m['r'] + ' دون اعتماد', 'يُعتمد كل إتلاف من مسؤول حماية البيانات قبل تنفيذه.'),
    (r'^P-12:retention:.+:stalled$', r'^Destruction (?P<r>\S+) approved', lambda m: 'الإتلاف ' + m['r'] + ' معتمد منذ أكثر من 30 يوماً ولم يُسجَّل تنفيذه', 'نفِّذه ووثِّق الدليل، أو ارفضه مع ذكر السبب.'),
    (r'^P-12:retention:[^:]+$', r'^"(?P<n>.*)" has no retention period$', lambda m: 'النشاط ' + _q(m['n']) + ' دون مدة احتفاظ', 'حدِّد مدة الاحتفاظ وخطوة الإتلاف أو إخفاء الهوية عند انتهائها.'),
    (r'^P-13:security:', r'^Security measure failing: (?P<t>.*)$', lambda m: 'إجراء أمني لا يجتاز الفحص: ' + m['t'], 'عالج الملاحظة في صفحة المدققين الآليين؛ يتحقق المتطلب عند نجاح الفحص.'),
    (r'^P-04:disc:.+:unmapped$', r'^(?P<s>.*) holds personal data \((?P<c>.*)\) but no processing activity names it$', lambda m: 'النظام ' + m['s'] + ' يحتوي بيانات شخصية (' + cats(m['c']) + ') ولا يذكره أي نشاط معالجة', 'سجِّل نشاط المعالجة لهذا النظام (الغرض، الأساس، الاحتفاظ، الجهات المستلمة) - زر «اعتماد كنشاط معالجة» يعبّئه من نتيجة الفحص.'),
    (r'^P-16:disc:.+:undeclared$', r'^(?P<s>.*): (?P<c>.*) data found that', lambda m: 'النظام ' + m['s'] + ': وُجدت ' + cats(m['c']) + ' لا تصرّح بها أنشطة المعالجة', 'أضف الفئات إلى النشاط (وتحقق أن الغرض يحتاجها - تقليل البيانات، المادة 11 من النظام).'),
    (r'^P-07:disc:.+:dpia$', r'^(?P<s>.*): sensitive data \((?P<c>.*)\) with no completed impact assessment$', lambda m: 'النظام ' + m['s'] + ': بيانات حساسة (' + cats(m['c']) + ') دون تقييم أثر مكتمل', 'شغِّل معالج تقييم الأثر للنشاط الذي يستخدم هذا النظام.'),
    (r'^P-05:consent:chain$', r'at entry (?P<e>\S+)$', lambda m: 'سجل الموافقات لا يجتاز فحص السلامة عند القيد ' + m['e'], 'تعامل معها كحادثة: سجلات الموافقة غير القابلة للتعديل تغيّرت. استعِد من النسخة الاحتياطية وتحقق ممن غيّرها.'),
    (r'^P-05:consent:.+:ropa$', r'^Consent purpose "(?P<n>.*)" is not linked', lambda m: 'غرض الموافقة ' + _q(m['n']) + ' غير مرتبط بنشاط معالجة', 'اربطه بنشاط المعالجة الذي يغطيه (سجل أنشطة المعالجة).'),
    (r'^P-05:consent:.+:silent$', r'^No consent has been recorded for "(?P<n>.*)" -', lambda m: 'لم تُسجَّل أي موافقة للغرض ' + _q(m['n']) + ' - النظام الجامع لا يرسل إلى السجل بعد', 'اربط البوابة أو التطبيق بمفتاح موافقة (سجل الموافقات ← المفاتيح) لتُسجَّل كل موافقة وكل سحب.'),
    (r'^P-05:consent:.+:stale$', r'^(?P<k>\d+) consent\(s\) for "(?P<n>.*)" were given under an older notice than version (?P<v>.*)$', lambda m: m['k'] + ' موافقة للغرض ' + _q(m['n']) + ' أُعطيت وفق إشعار أقدم من الإصدار ' + m['v'], 'التغيير الجوهري في الغرض أو الإشعار يحتاج موافقة جديدة: اطلبها من أصحاب البيانات، وأوقف المعالجة التي لا تغطيها الموافقة القديمة.'),
    (r'^P-05:consent:nokey$', r'', lambda m: 'لا يوجد مفتاح موافقة فعّال: لا يستطيع أي نظام إرسال الموافقات إلى السجل', 'أصدر مفتاحاً لكل نظام جامع للموافقات (البوابة، التطبيق، مركز الاتصال).'),
    (r'^sens:', r'^"(?P<n>.*)" \((?P<c>.*)\): (?P<k>\d+) control\(s\) missing$', lambda m: 'النشاط ' + _q(m['n']) + ' (' + cats(m['c']) + '): ' + m['k'] + ' من الضوابط ناقصة', 'طبِّق الضوابط الناقصة وسجِّلها (صفحة ضوابط البيانات الحساسة).'),
    (r'^ropa:.+:late$', r'^RoPA campaign "(?P<c>.*)": (?P<d>.*) not approved by (?P<t>.*)$', lambda m: 'حملة سجل المعالجة ' + _q(m['c']) + ': لم يُعتمد سجل إدارة ' + m['d'] + ' حتى ' + m['t'], 'ذكِّر مسؤول البيانات؛ ويراجع مسؤول حماية البيانات ما قُدِّم.'),
    (r'^ropa:.+:review$', r'^(?P<d>.*) submitted its RoPA over 7 days ago', lambda m: 'قدّمت إدارة ' + m['d'] + ' سجل المعالجة منذ أكثر من 7 أيام وهو بانتظار المراجعة', 'يعتمده مسؤول حماية البيانات (أو شخص غير مقدِّمه) أو يعيده مع الملاحظات.'),
    (r'^ropa:.+:steward$', r'^(?P<d>.*) has no data steward', lambda m: 'لا يوجد مسؤول بيانات في إدارة ' + m['d'] + ' لإكمال سجل المعالجة', 'سمِّ مسؤول البيانات في صفحة البرنامج.'),
    (r'^files:exposed:more$', r'^(?P<k>\d+) more exposed', lambda m: m['k'] + ' ملفاً إضافياً مكشوفاً يحتوي بيانات شخصية', 'افتح كتالوج البيانات، وصفِّ الملفات حسب الانكشاف، وعالجها واحداً تلو الآخر.'),
    (r'^files:.+:exposed$', r'^(?P<f>.*) \((?P<s>[^()]*)\) holds (?P<a>.*) and is (?P<h>.*)$', lambda m: 'الملف ' + m['f'] + ' (' + m['s'] + ') يحتوي ' + m['a'] + ' وهو ' + EXPOSE_AR.get(m['h'], m['h']), 'أزل الرابط أو الوصول الخارجي، أو قصر المجلد على من يحتاجه (المادة 19 من النظام: أمن البيانات الشخصية)؛ وانقله إلى النظام الأصلي إن كان نسخة.'),
    (r'^access:exc:', r'^(?P<k>\d+) access exception\(s\) not reviewed for over 7 days: (?P<t>.*)$', lambda m: m['k'] + ' استثناء وصول لم يُراجَع منذ أكثر من 7 أيام: ' + EXC_AR.get(m['t'], m['t']), 'راجع كل استثناء في صفحة سجل الوصول الحساس: مبرَّر (مع السبب) أو مُصعَّد. لا يراجع أحد وصوله هو.'),
    (r'^access:ind:', r'^Access pattern to review for (?P<u>.*) \((?P<k>\d+) indicator\(s\)\)$', lambda m: 'نمط وصول يحتاج مراجعة للمستخدم ' + m['u'] + ' (' + m['k'] + ' مؤشر)', 'راجع المؤشر: مؤشرات سلوكية وليست دليلاً. سجِّله مبرَّراً مع السبب، أو مُصعَّداً وفق سياسة الوصول.'),
    (r'^access:silent:', r'^System "(?P<n>.*)" has sent no access events', lambda m: 'النظام ' + _q(m['n']) + ' لم يرسل أحداث وصول منذ أكثر من 7 أيام', 'تحقق أن النظام ما زال يرسل سجل الوصول (المفتاح، الشبكة، المهمة) - الصمت لا يعني عدم وجود وصول.'),
    (r'^access:chain$', r'at entry (?P<e>\S+)$', lambda m: 'سجل الوصول الحساس لا يجتاز فحص السلامة عند القيد ' + m['e'], 'تعامل معها كحادثة: السجل غير القابل للتعديل تغيّر. استعِد من النسخة الاحتياطية وتحقق ممن غيّره.'),
    # vendor risk (pyengine/pdpl_vendor.py) and request intake (pyengine/pdpl_intake.py)
    (r'^vendor:.+:unrated$', r'^Vendor (?P<n>.*): risk not rated', lambda m: 'المورّد ' + _q(m['n']) + ': لم تُقيَّم مخاطره (لا يذكره أي نشاط معالجة)', 'أضف المورّد إلى أنشطة المعالجة التي يخدمها (سجلات المعالجة ← المعالجون).'),
    (r'^vendor:.+:due$', r'^Vendor (?P<n>.*) \((?P<t>\w+) risk\): (?P<w>.*)$', lambda m: 'المورّد ' + _q(m['n']) + ' (مخاطر ' + {'critical': 'حرجة', 'high': 'عالية', 'medium': 'متوسطة', 'low': 'منخفضة'}.get(m['t'], m['t']) + '): ' + ('لم يُقيَّم قط' if m['w'] == 'never assessed' else m['w'].replace('assessment due since', 'التقييم مستحق منذ')), 'ابدأ تقييم المورّد في صفحة معالجي البيانات وأرسل الاستبيان.'),
    (r'^vendor:.+:late$', r'^Vendor (?P<n>.*) has not returned the questionnaire \(due (?P<d>.*)\)$', lambda m: 'لم يُعِد المورّد ' + _q(m['n']) + ' الاستبيان (الموعد ' + m['d'] + ')', 'تابع مع المورّد؛ والمورّد الذي لا يجيب يُعد هو نفسه خطراً يجب تسجيله.'),
    (r'^vendor:.+:residual$', r'^Vendor (?P<n>.*): (?P<r>\w+) residual risk after assessment \(score (?P<s>.*)%\)$', lambda m: 'المورّد ' + _q(m['n']) + ': مخاطر متبقية ' + {'critical': 'حرجة', 'high': 'عالية'}.get(m['r'], m['r']) + ' بعد التقييم (النتيجة ' + m['s'] + '%)', 'نفِّذ إجراءات الحوكمة الناتجة عن التقييم، أو استبدل المورّد.'),
    (r'^intake:assignee$', r'', lambda m: 'تصل الطلبات تلقائياً ولم يُحدَّد مسؤول عنها', 'حدّد مسؤولاً افتراضياً (ومسؤولاً لكل نوع طلب عند الحاجة) في صفحة طلبات أصحاب البيانات ← الاستقبال.'),
    (r'^intake:verify$', r'^(?P<k>\d+) request', lambda m: m['k'] + ' طلب بانتظار التحقق من الهوية منذ أكثر من 5 أيام', 'تحقّق من هوية مقدمي الطلبات - تُحسب الثلاثون يوماً من تاريخ الاستلام لا من تاريخ التحقق.'),
    # recurring duties (pyengine/pdpl_office.py duties)
    (r'^duty:ropa-review:', r'^Annual review of "(?P<n>.*)" \((?P<i>.*)\)$', lambda m: 'المراجعة السنوية لنشاط المعالجة ' + _q(m['n']) + ' (' + m['i'] + ')', 'راجع السجل مع مالكه وحدِّث تاريخ المراجعة؛ تُغلق المهمة عندما يُظهر السجل المراجعة.'),
    (r'^duty:access-review:', r'^Access review of sensitive data in "(?P<n>.*)"$', lambda m: 'مراجعة صلاحيات الوصول إلى البيانات الحساسة في ' + _q(m['n']), 'راجع من يصل إلى البيانات وسجِّل تاريخ المراجعة في صفحة ضوابط البيانات الحساسة.'),
    (r'^duty:committee$', r'', lambda m: 'اجتماع لجنة الخصوصية (ربع سنوي)', 'اعقد الاجتماع وسجِّله في صفحة الحوكمة (الحضور، القرارات، الإجراءات).'),
    (r'^duty:programme-review$', r'', lambda m: 'المراجعة السنوية لبرنامج حماية البيانات', 'راجع البرنامج وسجِّل النتائج والإجراءات في صفحة الحوكمة.'),
    (r'^duty:training:', r'^PDPL training for (?P<d>.*)$', lambda m: 'التدريب على نظام حماية البيانات الشخصية لإدارة ' + m['d'], 'نفِّذ التدريب وسجِّله في صفحة البرنامج.'),
    (r'^duty:processor-review:', r'^Yearly review of processor "(?P<n>.*)"$', lambda m: 'المراجعة السنوية لمعالج البيانات ' + _q(m['n']), 'قيِّم المعالج وسجِّل التقييم في صفحة معالجي البيانات.'),
]
_T = [(re.compile(k), re.compile(t) if t else None, f, r) for k, t, f, r in T]


def translate(f):
    """{'title_ar', 'recommendation_ar'} for one finding (or duty), {} when the catalogue does not know it"""
    key, title = str(f.get('key') or ''), str(f.get('title') or '')
    for k, t, fn, rec in _T:
        if not k.search(key):
            continue
        m = t.search(title) if t else None
        if t and not m:
            continue
        g = {kk: (v or '') for kk, v in (m.groupdict() if m else {}).items()}
        return {'title_ar': fn(g), 'recommendation_ar': rec}
    return {}


# ---------------------------------------------------------------- the Privacy Office page: route map, organisation, routing
FN_AR = {'inventory': 'حصر البيانات وخرائطها', 'approval': 'اعتماد المعالجة والعقود', 'requests': 'طلبات أصحاب البيانات',
         'incidents': 'الاستجابة للحوادث وتسرّب البيانات', 'training': 'تدريب الموظفين والتوعية', 'sdaia': 'التواصل مع سدايا والتوثيق'}
_FN_LABEL_AR = {'Data inventory and mapping': FN_AR['inventory'], 'Processing approval and contracts': FN_AR['approval'], 'Data subject requests': FN_AR['requests'],
                'Security incident and breach response': FN_AR['incidents'], 'Staff training and awareness': FN_AR['training'], 'SDAIA liaison and documentation': FN_AR['sdaia']}
_ROLE_AR = {'data steward': 'مسؤول البيانات', 'deputy': 'نائب مسؤول البيانات', 'champion': 'سفير الخصوصية'}
_DUTY_WHY_AR = {'records of processing are reviewed at least yearly': 'تُراجَع سجلات أنشطة المعالجة مرة في السنة على الأقل',
                'access to sensitive data is reviewed every 6 months': 'تُراجَع صلاحيات الوصول إلى البيانات الحساسة كل 6 أشهر', 'the committee meets at least quarterly': 'تجتمع لجنة الخصوصية كل ربع سنة على الأقل',
                'the programme is reviewed at least once a year': 'يُراجَع برنامج حماية البيانات مرة في السنة على الأقل', 'staff who handle personal data are trained yearly': 'يُدرَّب الموظفون الذين يتعاملون مع البيانات الشخصية سنوياً',
                'processors are assessed periodically': 'يُقيَّم معالجو البيانات دورياً'}


def why_ar(w):
    """the routing reason (pdpl_office.route / duties) in Arabic; anything not recognised is kept as written"""
    x = str(w or '')
    m = re.match(r'^(data steward|deputy|champion) of (.+)$', x)
    if m:
        return 'بصفته ' + _ROLE_AR[m.group(1)] + ' في إدارة ' + m.group(2)
    m = re.match(r'^data owner of (.+)$', x)
    if m:
        return 'مالك بيانات النظام ' + m.group(1)
    m = re.match(r'^(deputy )?owner of (.+)$', x)
    if m:
        return ('نائب مالك وظيفة: ' if m.group(1) else 'مالك وظيفة: ') + _FN_LABEL_AR.get(m.group(2), m.group(2))
    if x.startswith('the DPO'):
        return 'مسؤول حماية البيانات (لم يُسمَّ شخص آخر لهذه المهمة)'
    if x.startswith('nobody named'):
        return 'لم يُسمَّ أحد - عيِّن مسؤول حماية البيانات ومالكي الوظائف'
    m = re.match(r'^assigned by ([^:]+): (.*)$', x)
    if m:
        return 'أسندها ' + m.group(1) + ': ' + m.group(2)
    return _DUTY_WHY_AR.get(x, x)


def gap_ar(g):
    x = str(g or '')
    m = re.match(r'^No owner for "(.+)" \(Governance\)$', x)
    if m:
        return 'لا يوجد مالك لوظيفة «' + _FN_LABEL_AR.get(m.group(1), m.group(1)) + '» (الحوكمة)'
    m = re.match(r'^(.+) has no data steward$', x)
    if m:
        return 'لا يوجد مسؤول بيانات في إدارة ' + m.group(1)
    m = re.match(r'^(.+) has no privacy champion$', x)
    if m:
        return 'لا يوجد سفير خصوصية في إدارة ' + m.group(1)
    if x.startswith('No DPO named'):
        return 'لم يُسمَّ مسؤول حماية البيانات (ملف حماية البيانات) - المهام غير الموجَّهة لا مسؤول عنها'
    if x.startswith('No privacy committee chair'):
        return 'لا يوجد رئيس للجنة الخصوصية - تصعيدات المستوى الثاني تذهب إلى مسؤول حماية البيانات'
    return x


STEP_AR = {
    'dpo': 'تعيين مسؤول حماية البيانات (يرتبط بالإدارة العليا وله صلاحية إيقاف المعالجة)', 'owners': 'تسمية مالك لكل وظيفة من وظائف حماية البيانات',
    'committee': 'تشكيل لجنة الخصوصية (رئيس، الشؤون القانونية، تقنية المعلومات، الموارد البشرية، العمليات) واجتماعها كل ربع سنة',
    'stewards': 'تسمية مسؤول بيانات وسفير خصوصية في كل إدارة', 'sdaia': 'التسجيل في المنصة الوطنية لحوكمة البيانات (سدايا) ونشر سياسة الخصوصية',
    'discover': 'اكتشاف البيانات الشخصية في قواعد البيانات وSharePoint وOneDrive ومجلدات المشاركة (كتالوج البيانات)',
    'ropa-campaign': 'تنفيذ حملة سجل المعالجة: كل إدارة تصف معالجتها للبيانات', 'ropa': 'إكمال سجل أنشطة المعالجة (المادة 33) والاحتفاظ به مدة المعالجة و5 سنوات بعدها',
    'basis': 'أساس نظامي لكل نشاط؛ موافقة صريحة للبيانات الحساسة والائتمانية والقرارات الآلية', 'lia': 'المصلحة المشروعة بتقييم مكتوب فقط، ولا تُستخدم للبيانات الحساسة',
    'consent': 'سجل الموافقات: موافقة قابلة للإثبات، وسحب بسهولة منحها، وإلغاء الاشتراك في التسويق',
    'dpia': 'تقييم الأثر قبل المعالجة عالية المخاطر (بيانات حساسة، مراقبة، قرارات آلية، دمج مصادر)', 'sensitive': 'ضوابط البيانات الحساسة والائتمانية (صلاحيات متدرجة، تشفير، إخفاء، تسجيل)',
    'transfers': 'النقل خارج المملكة: الأساس النظامي وتقييم مخاطر النقل (إعادة التأمين، مقدمو الخدمات، السحابة)', 'access-log': 'سجل الوصول الحساس من أنظمة المطالبات والطبية والاحتيال، بمراجعة بمبدأ العينين الأربع',
    'dsar': 'الإجابة عن طلبات أصحاب البيانات خلال 30 يوماً (التحقق من الهوية والبحث في كل الأنظمة)', 'breach': 'الاستجابة للتسرّب: مهلة 72 ساعة لسدايا، ومسار هيئة التأمين وساما والهيئة الوطنية للأمن السيبراني ومجلس الضمان الصحي، وإبلاغ الأشخاص عند احتمال الضرر',
    'processors': 'معالجو البيانات وفق شروط النظام، مُقيَّمون ومُراجَعون سنوياً، ومعالجون من الباطن معتمدون', 'retention': 'جدول احتفاظ لكل نشاط؛ وإتلاف منفَّذ وموثَّق (مع احترام الحجز النظامي)',
    'training': 'تدريب سنوي على النظام لكل إدارة تتعامل مع البيانات الشخصية', 'pbd': 'الخصوصية بالتصميم: مراجعة كل نظام أو تغيير جديد قبل التشغيل',
    'assess': 'التقييم الذاتي وإقرار مسؤول حماية البيانات والإدارة سنوياً', 'review': 'مراجعة سنوية للبرنامج؛ وكل ملاحظة إجراء له مالك وموعد',
}
PHASE_AR = {
    1: ('التعبئة والحوكمة', 'من المسؤول', ['مسؤول حماية البيانات', 'لجنة الخصوصية (الشؤون القانونية، تقنية المعلومات، الموارد البشرية، العمليات)', 'مالكو الوظائف', 'مسؤول بيانات وسفير خصوصية لكل إدارة'], 'الأسابيع 0-4 (تقدير)'),
    2: ('الاكتشاف والحصر', 'ما البيانات الشخصية لدينا وأين ولماذا', ['مسؤولو البيانات', 'مسؤولو قواعد البيانات ومالكو الأنظمة لحسابات الفحص للقراءة فقط', 'مراجعة مسؤول حماية البيانات'], 'الأسابيع 2-10 (تقدير)'),
    3: ('الأساس النظامي والشفافية', 'على أي أساس، وماذا يُبلَّغ الناس', ['الشؤون القانونية', 'مسؤول حماية البيانات', 'التسويق وخدمة العملاء للموافقات'], 'الأسابيع 6-12 (تقدير)'),
    4: ('ضوابط المخاطر', 'البيانات الحساسة والمعالجة عالية المخاطر والبيانات المنقولة خارج المملكة', ['مسؤول حماية البيانات', 'رئيس أمن المعلومات / الأمن السيبراني', 'مسؤولو بيانات الطبي والمطالبات وإعادة التأمين'], 'الأسابيع 8-16 (تقدير)'),
    5: ('الحقوق والجاهزية للتسرّب', 'الإجابة خلال 30 يوماً، والإبلاغ خلال 72 ساعة', ['خدمة العملاء (الطلبات)', 'مركز العمليات الأمنية / مالك الحوادث', 'الشؤون القانونية والالتزام للجهات الرقابية'], 'الأسابيع 10-16 (تقدير)'),
    6: ('المعالجون والاحتفاظ', 'معالجو البيانات ومن الباطن ومدة الاحتفاظ', ['المشتريات', 'الشؤون القانونية', 'مالكو الأنظمة للإتلاف'], 'الأسابيع 12-20 (تقدير)'),
    7: ('الأشخاص والثقافة', 'التدريب والخصوصية بالتصميم', ['الموارد البشرية / التدريب', 'سفراء الخصوصية', 'مديرو المشاريع'], 'الأسابيع 12-24 (تقدير)'),
    8: ('الضمان والاستدامة', 'التشغيل كل عام دون مشروع', ['مسؤول حماية البيانات', 'المراجعة الداخلية', 'اللجنة'], 'مستمر'),
}
MAINTAIN_AR = {'Daily': ('يومياً', 'توجيه المهام الجديدة؛ متابعة مهل الطلبات والتسرّب؛ مراجعة استثناءات الوصول الحساس', 'محرك مكتب الخصوصية، مسؤول حماية البيانات'),
               'Monthly': ('شهرياً', 'المهام المتأخرة والتصعيدات لدى مسؤول حماية البيانات؛ إعادة فحص كتالوج البيانات؛ المعالجون الجدد', 'مسؤول حماية البيانات، مالكو الوظائف'),
               'Quarterly': ('ربع سنوي', 'لجنة الخصوصية: التصعيدات وقبول المخاطر والقرارات', 'رئيس اللجنة'),
               '6-monthly': ('نصف سنوي', 'مراجعة صلاحيات الوصول إلى البيانات الحساسة لكل نشاط', 'مسؤولو البيانات / مالكو الأنظمة'),
               'Yearly': ('سنوياً', 'حملة سجل المعالجة ومراجعته، تحديث تقييمات الأثر، مراجعة المعالجين، التدريب، مراجعة البرنامج، الإقرار', 'مسؤول حماية البيانات، مسؤولو البيانات، المراجعة الداخلية')}
ROADMAP_NOTE_AR = 'كل خطوة تُقرأ من السجلات: مكتملة = مسجَّلة ولا ملاحظة مفتوحة؛ قيد التنفيذ = مسجَّلة وبها ملاحظات مفتوحة؛ لم تبدأ = لا شيء مسجَّل. المدد الزمنية تقديرات للتخطيط وتحديد الفريق، وليست قياسات.'
_NN = r'(\d+)'
_EV = [
    (r'^DPO: not named$', lambda m: 'مسؤول حماية البيانات: لم يُسمَّ'), (r'^DPO: (.+)$', lambda m: 'مسؤول حماية البيانات: ' + m.group(1)),
    (r'^%s of %s functions owned$' % (_NN, _NN), lambda m: m.group(1) + ' من ' + m.group(2) + ' وظائف لها مالك'),
    (r'^chair (.+), %s meeting\(s\)$' % _NN, lambda m: 'الرئيس ' + ('لم يُسمَّ' if m.group(1) == 'not named' else m.group(1)) + '، ' + m.group(2) + ' اجتماع'),
    (r'^%s of %s departments with a steward, %s with a champion$' % (_NN, _NN, _NN), lambda m: m.group(1) + ' من ' + m.group(2) + ' إدارات لها مسؤول بيانات، و' + m.group(3) + ' لها سفير خصوصية'),
    (r'^registered: (yes|no), privacy policy: (yes|no)$', lambda m: 'التسجيل: ' + ('نعم' if m.group(1) == 'yes' else 'لا') + '، سياسة الخصوصية: ' + ('نعم' if m.group(2) == 'yes' else 'لا')),
    (r'^%s source\(s\) scanned, %s read$' % (_NN, _NN), lambda m: 'فُحص ' + m.group(1) + ' مصدر، وقُرئ ' + m.group(2)),
    (r'^no campaign yet$', lambda m: 'لا توجد حملة بعد'),
    (r'^%s processing activities$' % _NN, lambda m: m.group(1) + ' نشاط معالجة'), (r'^%s activities, %s on consent$' % (_NN, _NN), lambda m: m.group(1) + ' نشاط، ' + m.group(2) + ' منها على الموافقة'),
    (r'^%s on legitimate interest$' % _NN, lambda m: m.group(1) + ' على المصلحة المشروعة'), (r'^%s consent purpose\(s\)$' % _NN, lambda m: m.group(1) + ' غرض موافقة'),
    (r'^%s signed DPIA\(s\)$' % _NN, lambda m: m.group(1) + ' تقييم أثر موقَّع'), (r'^%s sensitive activities, %s with controls recorded$' % (_NN, _NN), lambda m: m.group(1) + ' نشاط حساس، ' + m.group(2) + ' منها بضوابط مسجَّلة'),
    (r'^%s transfer\(s\) recorded$' % _NN, lambda m: m.group(1) + ' عملية نقل مسجَّلة'), (r'^%s system\(s\) sending access events$' % _NN, lambda m: m.group(1) + ' نظام يرسل أحداث الوصول'),
    (r'^%s request\(s\) recorded; requests owner (.+)$' % _NN, lambda m: m.group(1) + ' طلب مسجَّل؛ مالك الطلبات ' + ('لم يُسمَّ' if m.group(2) == 'not named' else m.group(2))),
    (r'^%s breach\(es\) recorded; incidents owner (.+)$' % _NN, lambda m: m.group(1) + ' حادثة تسرّب مسجَّلة؛ مالك الحوادث ' + ('لم يُسمَّ' if m.group(2) == 'not named' else m.group(2))),
    (r'^%s processor\(s\)$' % _NN, lambda m: m.group(1) + ' معالج بيانات'), (r'^%s retention rule\(s\), %s destruction run\(s\)$' % (_NN, _NN), lambda m: m.group(1) + ' قاعدة احتفاظ، ' + m.group(2) + ' دورة إتلاف'),
    (r'^%s of %s departments trained this year$' % (_NN, _NN), lambda m: m.group(1) + ' من ' + m.group(2) + ' إدارات تدرّبت هذا العام'), (r'^%s review\(s\)$' % _NN, lambda m: m.group(1) + ' مراجعة'),
    (r'^statement signed (.+)$', lambda m: 'الإقرار موقَّع ' + m.group(1)), (r'^statement not signed$', lambda m: 'الإقرار غير موقَّع'),
    (r'^last review (.+)$', lambda m: 'آخر مراجعة ' + m.group(1)), (r'^never reviewed$', lambda m: 'لم يُراجَع قط'),
]
_EVC = [(re.compile(p), f) for p, f in _EV]


def evidence_ar(e):
    x = str(e or '')
    if '; ' in x and 'departments approved' in x:   # RoPA campaigns: "<name>: a of b departments approved; …"
        return '؛ '.join(re.sub(r'^(.*): (\d+) of (\d+) departments approved$', r'\1: اعتُمدت \2 من \3 إدارات', p) for p in x.split('; '))
    m = re.match(r'^(.*): (\d+) of (\d+) departments approved$', x)
    if m:
        return m.group(1) + ': اعتُمدت ' + m.group(2) + ' من ' + m.group(3) + ' إدارات'
    for p, f in _EVC:
        m = p.match(x)
        if m:
            return f(m)
    return x


def _is_finding(o):
    return isinstance(o, dict) and isinstance(o.get('key'), str) and isinstance(o.get('title'), str) and o.get('severity') in ('critical', 'high', 'medium', 'low', 'info')


def annotate(out):
    """adds title_ar / recommendation_ar to every finding inside a PDPL answer (findings lists, nested results), and
    blockers_ar beside the statement's blockers. A finding the catalogue does not know keeps its English only. Returns out."""
    def walk(o, depth):
        if depth > 8:
            return
        if isinstance(o, list):
            for x in o:
                walk(x, depth + 1)
            return
        if not isinstance(o, dict):
            return
        if _is_finding(o) and not o.get('title_ar'):
            o.update(translate(o))
        for v in o.values():
            if isinstance(v, (dict, list)):
                walk(v, depth + 1)
        rd = o.get('readiness')
        if isinstance(rd, dict) and isinstance(rd.get('blockers'), list) and isinstance(o.get('findings'), list):
            rd['blockers_ar'] = blockers_ar(rd['blockers'], o['findings'])
    walk(out, 0)
    return out


_SEV_AR = {'critical': 'حرجة', 'high': 'عالية', 'medium': 'متوسطة', 'low': 'منخفضة'}


def blockers_ar(blockers, findings):
    """the statement's open items in Arabic: "open <sev> finding: <title>" takes the finding's Arabic title; requirement
    lines are returned as written (the page's dictionary translates them)"""
    by_title = {}
    for f in findings:
        if isinstance(f, dict) and isinstance(f.get('title'), str):
            ar = f.get('title_ar') or translate(f).get('title_ar')
            if ar:
                by_title[f['title']] = ar
    out = []
    for b in blockers:
        m = re.match(r'^open (critical|high|medium|low) finding: (.*)$', str(b), re.S)
        out.append('ملاحظة ' + _SEV_AR[m.group(1)] + ' مفتوحة: ' + by_title[m.group(2)] if m and m.group(2) in by_title else b)
    return out
