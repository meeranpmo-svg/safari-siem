// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * policy-templates.js - bilingual (English / Arabic) policy templates for the Compliance AI Assistant (compliance-copilot.js).
 * Original wording written for an operations & maintenance group with head office, branches and project sites; each section
 * names the framework clauses it serves so a reviewer can trace it. They are STARTING DRAFTS: the policy owner adapts them, a
 * second person approves them in GRC (four-eyes) - nothing here is published by itself. References: NCA ECC-1:2018 subdomains,
 * ISO/IEC 27001:2022 Annex A controls, the Saudi PDPL articles, the NDMO Data Management and Personal Data Protection Standards
 * domains; Aramco CCC is named by topic only (the organisation imports SACS-002 itself). Verify every reference against the
 * current text of each framework before approval.
 * Placeholders: {company} {company_ar} {owner} {owner_ar} {review_months} {pw_min} {lockout} {access_review_months}
 *               {retention_years} {backup_days} {rto_hours} {log_days} {patch_critical_days} {breach_hours}
 */
const ROLES = {
  ciso: { en: 'Head of Information Security', ar: 'رئيس أمن المعلومات' },
  it: { en: 'IT Manager', ar: 'مدير تقنية المعلومات' },
  dpo: { en: 'Data Protection Officer', ar: 'مسؤول حماية البيانات الشخصية' },
  cdo: { en: 'Data Management Officer', ar: 'مسؤول إدارة البيانات' },
  hr: { en: 'HR Manager', ar: 'مدير الموارد البشرية' },
  ops: { en: 'Operations Manager', ar: 'مدير العمليات' },
};
const DEFAULTS = { review_months: 12, pw_min: 12, lockout: 5, access_review_months: 3, retention_years: 5, backup_days: 30, rto_hours: 24, log_days: 365, patch_critical_days: 14, breach_hours: 72 };
const S = (en_h, ar_h, en, ar) => ({ h: { en: en_h, ar: ar_h }, p: { en, ar } });
const COMMON_END = [
  S('Exceptions', 'الاستثناءات',
    'An exception to this policy is requested in writing with the business reason, the compensating control and an end date. It is approved by the {owner} and a second manager, recorded in the risk register and reviewed before it expires.',
    'يُطلب أي استثناء من هذه السياسة كتابياً مع بيان المبرر التشغيلي والضابط البديل وتاريخ الانتهاء، ويعتمده {owner_ar} ومدير آخر، ويُسجَّل في سجل المخاطر ويُراجَع قبل انتهائه.'),
  S('Compliance and review', 'الالتزام والمراجعة',
    'Breaches of this policy are handled under the disciplinary procedure of {company}. The {owner} reviews this policy at least every {review_months} months, and after any major incident, organisational change or change in regulation.',
    'تُعالَج مخالفات هذه السياسة وفق الإجراءات التأديبية المعتمدة في {company_ar}. ويراجع {owner_ar} هذه السياسة مرة كل {review_months} شهراً على الأقل، وبعد أي حادث جوهري أو تغيير تنظيمي أو تشريعي.'),
];

const TEMPLATES = [
  { id: 'infosec', owner: 'ciso', title: { en: 'Information Security Policy', ar: 'سياسة أمن المعلومات' },
    refs: { nca: ['1-3', '1-4', '1-5'], iso: ['5.1', '5.2', '5.4'], pdpl: [], ndmo: ['Data Security and Protection'], aramco: 'Cybersecurity governance' },
    sections: [
      S('Purpose', 'الغرض',
        'This policy sets how {company} protects the confidentiality, integrity and availability of its information, its systems and the services it delivers to clients at head office, branches and project sites.',
        'تحدد هذه السياسة كيف تحمي {company_ar} سرية معلوماتها وسلامتها وتوافرها، وكذلك أنظمتها والخدمات التي تقدمها لعملائها في المقر الرئيسي والفروع ومواقع المشاريع.'),
      S('Scope', 'النطاق',
        'All employees, site workforce, contractors and visitors of {company}; all information in any form; all systems, devices, networks and cloud services owned or used by the company, including those at client sites.',
        'تنطبق على جميع موظفي {company_ar} والعاملين في المواقع والمقاولين والزوار، وعلى جميع المعلومات بأي شكل كانت، وعلى جميع الأنظمة والأجهزة والشبكات والخدمات السحابية المملوكة للشركة أو المستخدمة لديها، بما في ذلك ما يوجد في مواقع العملاء.'),
      S('Governance', 'الحوكمة',
        'Executive management approves this policy and provides the resources to apply it. The {owner} leads the information security function, reports to executive management independently of IT operations, and maintains the supporting policies and procedures.',
        'تعتمد الإدارة التنفيذية هذه السياسة وتوفر الموارد اللازمة لتطبيقها. ويقود {owner_ar} وظيفة أمن المعلومات، ويرفع تقاريره إلى الإدارة التنفيذية باستقلال عن عمليات تقنية المعلومات، ويحافظ على السياسات والإجراءات الداعمة.'),
      S('Risk management', 'إدارة المخاطر',
        'Information security risks are identified, assessed and treated at least once a year and before new systems, sites or client contracts start. Each risk has an owner and a treatment decision recorded in the risk register.',
        'تُحدَّد مخاطر أمن المعلومات وتُقيَّم وتُعالَج مرة واحدة سنوياً على الأقل، وقبل بدء أي نظام أو موقع أو عقد جديد مع العملاء. ولكل خطر مالك وقرار معالجة مسجل في سجل المخاطر.'),
      S('Responsibilities', 'المسؤوليات',
        'Every person protects the information they handle and reports suspected incidents at once. Managers make sure their staff and contractors know and follow this policy. Department heads own the information and systems of their department.',
        'يحمي كل شخص المعلومات التي يتعامل معها ويبلغ فوراً عن أي حادث مشتبه به. ويتأكد المديرون من معرفة موظفيهم ومقاوليهم بهذه السياسة والتزامهم بها. ويتولى رؤساء الإدارات ملكية معلومات إداراتهم وأنظمتها.'),
      S('Awareness', 'التوعية',
        'All staff complete security awareness training when they join and every year, including the site workforce in a language they understand. Phishing exercises are run at least every quarter.',
        'يُكمل جميع الموظفين التدريب على التوعية الأمنية عند الالتحاق وسنوياً، بما في ذلك العاملون في المواقع وباللغة التي يفهمونها. وتُنفَّذ تمارين التصيّد الاحتيالي مرة كل ربع سنة على الأقل.'),
    ].concat(COMMON_END) },
  { id: 'aup', owner: 'it', title: { en: 'Acceptable Use Policy', ar: 'سياسة الاستخدام المقبول' },
    refs: { nca: ['1-9', '2-1'], iso: ['5.10', '6.2', '8.1'], pdpl: [], ndmo: [], aramco: 'Acceptable use' },
    sections: [
      S('Purpose', 'الغرض', 'This policy states how the devices, accounts, email and internet of {company} may be used.', 'تحدد هذه السياسة كيفية استخدام أجهزة {company_ar} وحساباتها وبريدها الإلكتروني وخدمة الإنترنت فيها.'),
      S('Business use', 'الاستخدام لأغراض العمل',
        'Company devices and accounts are for company business. Limited personal use is allowed if it does not affect work, security or the reputation of {company}. Users have no expectation of privacy for company systems, which are monitored as the law allows.',
        'تُستخدم أجهزة الشركة وحساباتها لأغراض العمل. ويُسمح بالاستخدام الشخصي المحدود إذا لم يؤثر على العمل أو الأمن أو سمعة {company_ar}. ولا يتوقع المستخدم الخصوصية في أنظمة الشركة التي تخضع للمراقبة في حدود ما يسمح به النظام.'),
      S('Not allowed', 'الممنوعات',
        'Sharing passwords or accounts; installing unapproved software; connecting unapproved devices or USB storage; disabling antivirus or encryption; sending company or client data to personal email or personal cloud storage; using company systems for anything unlawful or offensive.',
        'مشاركة كلمات المرور أو الحسابات؛ تثبيت برامج غير معتمدة؛ توصيل أجهزة أو وسائط تخزين USB غير معتمدة؛ تعطيل برامج مكافحة الفيروسات أو التشفير؛ إرسال بيانات الشركة أو العملاء إلى بريد أو تخزين سحابي شخصي؛ استخدام أنظمة الشركة لأي غرض مخالف للأنظمة أو مسيء.'),
      S('Client sites', 'مواقع العملاء',
        'At client sites, staff also follow the client\'s rules for devices, photography, removable media and network access. Client information is used only for the contract it was given for.',
        'يلتزم الموظفون في مواقع العملاء أيضاً بقواعد العميل المتعلقة بالأجهزة والتصوير ووسائط التخزين وصلاحيات الشبكة. وتُستخدم معلومات العميل فقط لأغراض العقد الذي قُدِّمت من أجله.'),
      S('Leaving the company', 'ترك العمل',
        'On the last working day all devices, badges and tokens are returned, and access is removed the same day through the HR offboarding process.',
        'تُعاد جميع الأجهزة والبطاقات ورموز الدخول في آخر يوم عمل، وتُلغى الصلاحيات في اليوم نفسه من خلال إجراءات إنهاء الخدمة في الموارد البشرية.'),
    ].concat(COMMON_END) },
  { id: 'access', owner: 'ciso', title: { en: 'Access Control and Password Policy', ar: 'سياسة التحكم في الوصول وكلمات المرور' },
    refs: { nca: ['2-2'], iso: ['5.15', '5.16', '5.17', '5.18', '8.2', '8.5'], pdpl: ['19'], ndmo: ['Data Security and Protection'], aramco: 'Identity and access management' },
    sections: [
      S('Principles', 'المبادئ', 'Access is given on the need-to-know and least-privilege principles, to named accounts only, approved by the information owner.', 'تُمنح الصلاحيات وفق مبدأي الحاجة إلى المعرفة والحد الأدنى من الصلاحيات، ولحسابات بأسماء أصحابها فقط، وبعد موافقة مالك المعلومات.'),
      S('Joiners, movers, leavers', 'الالتحاق والانتقال وإنهاء الخدمة',
        'Accounts are created from an approved HR request, changed when a person changes role, and disabled on the last working day. Access not removed within one working day is reported to the {owner}.',
        'تُنشأ الحسابات بناءً على طلب معتمد من الموارد البشرية، وتُعدَّل عند تغيير الوظيفة، وتُعطَّل في آخر يوم عمل. ويُبلَّغ {owner_ar} عن أي صلاحية لم تُلغَ خلال يوم عمل واحد.'),
      S('Passwords and multi-factor authentication', 'كلمات المرور والتحقق متعدد العوامل',
        'Passwords are at least {pw_min} characters with letters, digits and a symbol, are never shared or written down, and accounts lock after {lockout} failed attempts. Multi-factor authentication is required for email, remote access, cloud services, the ERP and every administrator account.',
        'لا يقل طول كلمة المرور عن {pw_min} حرفاً، وتتضمن أحرفاً وأرقاماً ورمزاً، ولا تُشارَك ولا تُكتب، ويُقفل الحساب بعد {lockout} محاولات فاشلة. ويُشترط التحقق متعدد العوامل للبريد الإلكتروني والوصول عن بُعد والخدمات السحابية ونظام تخطيط الموارد (ERP) وجميع حسابات المسؤولين.'),
      S('Privileged access', 'الصلاحيات المميزة',
        'Administrators use a separate administrator account for administration only. Privileged access is limited in number, logged, and approved by a second person; shared or default administrator accounts are disabled.',
        'يستخدم المسؤولون حساباً إدارياً منفصلاً للأعمال الإدارية فقط. وتُقيَّد الصلاحيات المميزة في العدد، وتُسجَّل، وتُعتمد من شخص ثانٍ، وتُعطَّل الحسابات الإدارية المشتركة أو الافتراضية.'),
      S('Access reviews', 'مراجعة الصلاحيات',
        'Owners review the access to their systems every {access_review_months} months, including the ERP roles and segregation of duties. Access no longer needed is removed and the review is kept as evidence.',
        'يراجع ملاك الأنظمة الصلاحيات على أنظمتهم كل {access_review_months} أشهر، بما في ذلك أدوار نظام تخطيط الموارد (ERP) وفصل المهام. وتُلغى الصلاحيات غير اللازمة، ويُحتفظ بالمراجعة كدليل.'),
    ].concat(COMMON_END) },
  { id: 'pdpl', owner: 'dpo', title: { en: 'Personal Data Protection Policy', ar: 'سياسة حماية البيانات الشخصية' },
    refs: { nca: ['2-7'], iso: ['5.34'], pdpl: ['4', '5', '11', '12', '18', '19', '20', '22', '29'], ndmo: ['Personal Data Protection'], aramco: 'Data protection' },
    sections: [
      S('Purpose and scope', 'الغرض والنطاق',
        'This policy applies the Personal Data Protection Law (PDPL) and its implementing regulations to all personal data processed by {company}: employees and site workforce (including identity, iqama, payroll and medical data), job applicants, client contacts, visitors and suppliers.',
        'تطبق هذه السياسة نظام حماية البيانات الشخصية ولوائحه التنفيذية على جميع البيانات الشخصية التي تعالجها {company_ar}: الموظفون والعاملون في المواقع (بما في ذلك بيانات الهوية والإقامة والرواتب والبيانات الطبية)، والمتقدمون للوظائف، وجهات اتصال العملاء، والزوار، والموردون.'),
      S('Principles', 'المبادئ',
        'Personal data is collected for a specified, lawful purpose, limited to what is needed, kept accurate, kept no longer than necessary and protected. A record of processing activities is kept for every purpose.',
        'تُجمع البيانات الشخصية لغرض محدد ومشروع، وتقتصر على الحد الأدنى اللازم، وتُحفظ دقيقة ومحدَّثة، ولا تُحتفظ بها أطول من اللازم، وتُحمى بالضوابط المناسبة. ويُحفظ سجل لأنشطة المعالجة لكل غرض.'),
      S('Notice and consent', 'الإشعار والموافقة',
        'People are told, in Arabic and in a language they understand, what is collected, why, who receives it and their rights. Where processing relies on consent, consent is recorded and can be withdrawn as easily as it was given.',
        'يُبلَّغ الأشخاص باللغة العربية وبلغة يفهمونها بما يُجمع ولماذا ومن يتلقاه وبحقوقهم. وعندما تعتمد المعالجة على الموافقة، تُسجَّل الموافقة ويمكن سحبها بالسهولة نفسها التي مُنحت بها.'),
      S('Rights of the data subject', 'حقوق صاحب البيانات',
        'Requests to be informed, to access, to correct or to destroy personal data are logged, verified and answered within the period set by the regulations. The {owner} tracks every request to closure.',
        'تُسجَّل طلبات العلم بالبيانات والوصول إليها وتصحيحها وإتلافها، ويُتحقق من هوية مقدمها، ويُرد عليها خلال المدة المحددة في اللوائح. ويتابع {owner_ar} كل طلب حتى إغلاقه.'),
      S('Security, processors and transfers', 'الأمن والمعالجون والنقل خارج المملكة',
        'Personal data is protected by access control, encryption where needed and logging. Processors sign a data processing agreement before receiving data. Transfers outside the Kingdom take place only where the law and its regulations allow, after an assessment recorded by the {owner}.',
        'تُحمى البيانات الشخصية بضوابط الوصول والتشفير عند الحاجة وتسجيل الأحداث. ويوقّع المعالجون اتفاقية معالجة بيانات قبل استلامها. ولا تُنقل البيانات خارج المملكة إلا في الحالات التي يجيزها النظام ولوائحه وبعد تقييم يوثقه {owner_ar}.'),
      S('Impact assessment and breaches', 'تقييم الأثر وتسرب البيانات',
        'A data protection impact assessment is completed before new processing that may harm people. A personal data breach is reported to the {owner} at once; the competent authority is notified within {breach_hours} hours where the regulations require it, and affected people are informed when needed.',
        'يُجرى تقييم أثر حماية البيانات قبل أي معالجة جديدة قد تُلحق ضرراً بالأشخاص. ويُبلَّغ {owner_ar} فوراً عن أي تسرب للبيانات الشخصية، وتُخطَر الجهة المختصة خلال {breach_hours} ساعة متى ما اشترطت اللوائح ذلك، ويُبلَّغ المتأثرون عند الحاجة.'),
    ].concat(COMMON_END) },
  { id: 'classification', owner: 'cdo', title: { en: 'Data Classification and Handling Policy', ar: 'سياسة تصنيف البيانات والتعامل معها' },
    refs: { nca: ['2-7'], iso: ['5.12', '5.13', '5.14'], pdpl: ['19'], ndmo: ['Data Classification', 'Data Governance'], aramco: 'Data classification' },
    sections: [
      S('Levels', 'مستويات التصنيف',
        'Information of {company} is classified as Top Secret, Secret, Restricted or Public, following the national data classification levels. Unclassified information is handled as Restricted until it is classified.',
        'تُصنَّف معلومات {company_ar} إلى: سري للغاية، سري، مقيد، عام، وفق مستويات التصنيف الوطنية للبيانات. وتُعامَل المعلومات غير المصنفة على أنها مقيدة إلى أن تُصنَّف.'),
      S('Owners', 'ملاك البيانات', 'Each data set has an owner who classifies it, approves access to it and reviews its classification every year.', 'لكل مجموعة بيانات مالك يتولى تصنيفها واعتماد الوصول إليها ومراجعة تصنيفها سنوياً.'),
      S('Handling', 'التعامل',
        'Restricted and higher information is shared only with people who need it, sent encrypted outside the company, not stored on personal devices or personal cloud, and printed only when necessary and collected at once. Client information takes the client\'s classification where it is stricter.',
        'لا تُشارك المعلومات المقيدة وما فوقها إلا مع من يحتاجها، وتُرسل مشفرة خارج الشركة، ولا تُخزَّن على أجهزة أو خدمات سحابية شخصية، ولا تُطبع إلا عند الضرورة مع استلامها فوراً. وتأخذ معلومات العميل تصنيف العميل إذا كان أشد.'),
      S('Labelling', 'الوسم', 'Documents and emails carry their classification label; the Microsoft 365 sensitivity labels apply the same levels.', 'تحمل المستندات ورسائل البريد الإلكتروني وسم التصنيف الخاص بها، وتطبق تسميات الحساسية في Microsoft 365 المستويات نفسها.'),
    ].concat(COMMON_END) },
  { id: 'retention', owner: 'cdo', title: { en: 'Data Retention and Disposal Policy', ar: 'سياسة الاحتفاظ بالبيانات وإتلافها' },
    refs: { nca: ['2-7'], iso: ['5.33', '8.10'], pdpl: ['18'], ndmo: ['Document and Content Management', 'Data Operations'], aramco: 'Data protection' },
    sections: [
      S('Retention', 'الاحتفاظ',
        'Each record type has a retention period in the retention schedule, set by law, contract or business need. Unless the schedule says otherwise, business records are kept for {retention_years} years after the end of the related activity.',
        'لكل نوع من السجلات مدة احتفاظ محددة في جدول الاحتفاظ بناءً على النظام أو العقد أو حاجة العمل. وما لم ينص الجدول على خلاف ذلك، يُحتفظ بسجلات الأعمال مدة {retention_years} سنوات بعد انتهاء النشاط المرتبط بها.'),
      S('Personal data', 'البيانات الشخصية', 'Personal data is destroyed or anonymised when the purpose ends, unless the law requires it to be kept; the reason for keeping it is recorded.', 'تُتلف البيانات الشخصية أو تُجعل مجهولة الهوية عند انتهاء الغرض منها، ما لم يوجب النظام الاحتفاظ بها، ويُوثَّق سبب الاحتفاظ.'),
      S('Disposal', 'الإتلاف',
        'Paper is shredded; disks and devices are wiped with an approved method or physically destroyed, with a certificate kept. Disposal of Restricted and higher data is approved by the data owner.',
        'تُفرم المستندات الورقية، وتُمسح الأقراص والأجهزة بطريقة معتمدة أو تُتلف مادياً مع الاحتفاظ بشهادة إتلاف. ويعتمد مالك البيانات إتلاف البيانات المقيدة وما فوقها.'),
      S('Legal hold', 'التجميد النظامي', 'Records under investigation, dispute or legal hold are not destroyed until the hold is lifted in writing.', 'لا تُتلف السجلات الخاضعة لتحقيق أو نزاع أو تجميد نظامي حتى يُرفع التجميد كتابياً.'),
    ].concat(COMMON_END) },
  { id: 'backup', owner: 'it', title: { en: 'Backup and Recovery Policy', ar: 'سياسة النسخ الاحتياطي والاستعادة' },
    refs: { nca: ['2-9', '3-1'], iso: ['8.13', '5.30'], pdpl: ['19'], ndmo: ['Data Operations'], aramco: 'Backup and recovery' },
    sections: [
      S('What is backed up', 'ما يُنسخ احتياطياً', 'All servers, databases (including the ERP), file shares, Microsoft 365 data and network device configurations are backed up according to the backup schedule.', 'تُنسخ احتياطياً جميع الخوادم وقواعد البيانات (بما فيها نظام تخطيط الموارد ERP) ومجلدات الملفات المشتركة وبيانات Microsoft 365 وإعدادات أجهزة الشبكة وفق جدول النسخ الاحتياطي.'),
      S('Frequency and retention', 'التكرار ومدة الاحتفاظ', 'Critical systems are backed up at least daily and kept for at least {backup_days} days, with one copy offline or immutable and one copy in a separate location.', 'تُنسخ الأنظمة الحرجة احتياطياً يومياً على الأقل ويُحتفظ بالنسخ مدة لا تقل عن {backup_days} يوماً، مع نسخة غير متصلة أو غير قابلة للتعديل ونسخة في موقع منفصل.'),
      S('Recovery', 'الاستعادة', 'Each critical system has a recovery time objective; the default is {rto_hours} hours. Backups are encrypted and access to them is restricted to the backup administrators.', 'لكل نظام حرج هدف زمني للاستعادة، والافتراضي {rto_hours} ساعة. وتُشفَّر النسخ الاحتياطية ويُقيَّد الوصول إليها على مسؤولي النسخ الاحتياطي.'),
      S('Testing', 'الاختبار', 'A restore is tested every quarter for a sample of systems and a full disaster recovery exercise is run every year; results and fixes are recorded.', 'يُختبر الاستعداد للاستعادة كل ربع سنة لعينة من الأنظمة، ويُنفَّذ تمرين كامل للتعافي من الكوارث سنوياً، وتُوثَّق النتائج والإجراءات التصحيحية.'),
    ].concat(COMMON_END) },
  { id: 'incident', owner: 'ciso', title: { en: 'Cybersecurity Incident Response Policy', ar: 'سياسة الاستجابة لحوادث الأمن السيبراني' },
    refs: { nca: ['2-13'], iso: ['5.24', '5.25', '5.26', '5.27', '5.28', '6.8'], pdpl: ['20'], ndmo: ['Data Security and Protection'], aramco: 'Incident management' },
    sections: [
      S('Reporting', 'الإبلاغ', 'Anyone who suspects an incident - a phishing email, a lost device, unusual system behaviour, data sent to the wrong person - reports it at once to the IT service desk or the {owner}.', 'يبلغ أي شخص يشتبه في حادث - كرسالة تصيد، أو فقدان جهاز، أو سلوك غير معتاد للنظام، أو إرسال بيانات إلى شخص خاطئ - فوراً مكتب خدمة تقنية المعلومات أو {owner_ar}.'),
      S('Response', 'الاستجابة', 'Incidents are triaged by severity, contained, eradicated and recovered following the incident response plan, with evidence preserved. Critical incidents are escalated to executive management.', 'تُصنَّف الحوادث حسب خطورتها، ثم تُحتوى وتُزال آثارها ويُستعاد العمل وفق خطة الاستجابة للحوادث مع حفظ الأدلة. وتُصعَّد الحوادث الحرجة إلى الإدارة التنفيذية.'),
      S('Notification', 'الإخطار', 'Incidents are reported to the National Cybersecurity Authority and other authorities as the regulations require; personal data breaches follow the Personal Data Protection Policy ({breach_hours} hours). Affected clients are informed as their contracts require.', 'يُبلَّغ عن الحوادث إلى الهيئة الوطنية للأمن السيبراني والجهات الأخرى وفق ما تتطلبه الأنظمة، ويُتبع في تسرب البيانات الشخصية ما ورد في سياسة حماية البيانات الشخصية ({breach_hours} ساعة). ويُبلَّغ العملاء المتأثرون وفق ما تقتضيه عقودهم.'),
      S('Lessons learned', 'الدروس المستفادة', 'Every major incident is closed with a review of the cause and the actions to prevent it happening again; the plan is exercised every year.', 'يُغلق كل حادث جوهري بمراجعة لأسبابه والإجراءات اللازمة لمنع تكراره، ويُختبر تطبيق الخطة سنوياً.'),
    ].concat(COMMON_END) },
  { id: 'thirdparty', owner: 'ciso', title: { en: 'Third-Party and Contractor Security Policy', ar: 'سياسة أمن الأطراف الخارجية والمقاولين' },
    refs: { nca: ['4-1', '4-2'], iso: ['5.19', '5.20', '5.21', '5.22', '5.23'], pdpl: ['19'], ndmo: ['Data Sharing and Interoperability'], aramco: 'Third-party cybersecurity (SACS-002)' },
    sections: [
      S('Before the contract', 'قبل التعاقد', 'Suppliers and subcontractors that access company or client information, systems or sites are assessed for cybersecurity risk before the contract, in proportion to the access they will have.', 'يُقيَّم الموردون والمقاولون من الباطن الذين يصلون إلى معلومات الشركة أو العملاء أو أنظمتها أو مواقعها من حيث مخاطر الأمن السيبراني قبل التعاقد، بما يتناسب مع مستوى الوصول الممنوح لهم.'),
      S('In the contract', 'في العقد', 'Contracts include confidentiality, security requirements, incident notification, the right to audit, data return and destruction at the end, and data processing terms where personal data is involved.', 'تتضمن العقود بنود السرية ومتطلبات الأمن والإبلاغ عن الحوادث وحق التدقيق وإعادة البيانات وإتلافها عند انتهاء العقد، وشروط معالجة البيانات عند وجود بيانات شخصية.'),
      S('Access', 'الوصول', 'Third parties get named accounts with multi-factor authentication, only for the period and systems needed; remote vendor sessions are approved, time-limited and recorded.', 'يحصل الأطراف الخارجيون على حسابات بأسمائهم مع التحقق متعدد العوامل، وللمدة والأنظمة اللازمة فقط، وتُعتمد جلسات الوصول عن بُعد للموردين وتُحدَّد مدتها وتُسجَّل.'),
      S('As a supplier to clients', 'بصفتنا مورداً للعملاء', '{company} meets the cybersecurity requirements of its clients - including the Saudi Aramco Third Party Cybersecurity Standard where it applies - and keeps the required certificates valid before contract work starts.', 'تلتزم {company_ar} بمتطلبات الأمن السيبراني لعملائها - بما في ذلك معيار أرامكو السعودية للأمن السيبراني للأطراف الخارجية متى ما انطبق - وتحافظ على سريان الشهادات المطلوبة قبل بدء أعمال العقد.'),
    ].concat(COMMON_END) },
  { id: 'remote', owner: 'it', title: { en: 'Remote Work and Mobile Device Policy', ar: 'سياسة العمل عن بُعد والأجهزة المحمولة' },
    refs: { nca: ['2-6'], iso: ['6.7', '8.1'], pdpl: ['19'], ndmo: [], aramco: 'Mobile and remote access' },
    sections: [
      S('Remote access', 'الوصول عن بُعد', 'Remote work is approved by the line manager. Company systems are reached only through the company VPN or approved cloud services with multi-factor authentication.', 'يُعتمد العمل عن بُعد من المدير المباشر، ولا يتم الوصول إلى أنظمة الشركة إلا عبر الشبكة الافتراضية الخاصة (VPN) أو الخدمات السحابية المعتمدة مع التحقق متعدد العوامل.'),
      S('Devices', 'الأجهزة', 'Laptops and phones that hold company data are enrolled in device management, encrypted, protected by a PIN or password and kept up to date. Lost or stolen devices are reported at once so they can be wiped.', 'تُسجَّل الحواسيب والهواتف التي تحتوي على بيانات الشركة في نظام إدارة الأجهزة، وتكون مشفرة ومحمية برمز أو كلمة مرور ومحدَّثة. ويُبلَّغ فوراً عن الأجهزة المفقودة أو المسروقة لمسحها عن بُعد.'),
      S('Working outside the office', 'العمل خارج المكتب', 'Screens are locked when unattended, public Wi-Fi is used only through the VPN, and conversations about Restricted information are not held in public places.', 'تُقفل الشاشات عند الابتعاد عنها، ولا تُستخدم شبكات Wi-Fi العامة إلا عبر الشبكة الافتراضية الخاصة، ولا تُناقش المعلومات المقيدة في الأماكن العامة.'),
    ].concat(COMMON_END) },
  { id: 'logging', owner: 'ciso', title: { en: 'Logging and Monitoring Policy', ar: 'سياسة تسجيل الأحداث والمراقبة' },
    refs: { nca: ['2-12'], iso: ['8.15', '8.16', '8.17'], pdpl: ['19'], ndmo: ['Data Security and Protection'], aramco: 'Logging and monitoring' },
    sections: [
      S('What is logged', 'ما يُسجَّل', 'Servers, firewalls, switches, the ERP, Microsoft 365, Active Directory and security tools send their security events to the central SIEM: sign-ins, privileged actions, changes, access to Restricted data and security alerts.', 'ترسل الخوادم وجدران الحماية والمحولات ونظام تخطيط الموارد ERP وMicrosoft 365 والدليل النشط وأدوات الأمن أحداثها الأمنية إلى نظام إدارة المعلومات والأحداث الأمنية (SIEM) المركزي: تسجيلات الدخول، والإجراءات المميزة، والتغييرات، والوصول إلى البيانات المقيدة، والتنبيهات الأمنية.'),
      S('Retention and protection', 'الاحتفاظ والحماية', 'Security logs are kept for at least {log_days} days, protected from change and readable only by authorised staff. All systems take their time from the company NTP servers.', 'يُحتفظ بسجلات الأمن مدة لا تقل عن {log_days} يوماً، وتُحمى من التعديل، ولا يطلع عليها إلا الموظفون المصرح لهم. وتأخذ جميع الأنظمة توقيتها من خوادم NTP الخاصة بالشركة.'),
      S('Monitoring', 'المراقبة', 'Alerts are reviewed every day by the security operations team; critical alerts are handled under the Incident Response Policy. Systems that stop sending logs are investigated.', 'يراجع فريق العمليات الأمنية التنبيهات يومياً، وتُعالج التنبيهات الحرجة وفق سياسة الاستجابة للحوادث، ويُحقَّق في أي نظام يتوقف عن إرسال سجلاته.'),
    ].concat(COMMON_END) },
  { id: 'change_patch', owner: 'it', title: { en: 'Change, Vulnerability and Patch Management Policy', ar: 'سياسة إدارة التغيير والثغرات والتحديثات' },
    refs: { nca: ['2-10', '2-11', '1-6'], iso: ['8.8', '8.9', '8.32'], pdpl: [], ndmo: [], aramco: 'Vulnerability and patch management' },
    sections: [
      S('Changes', 'التغييرات', 'Changes to production systems and network devices are requested, risk-assessed, approved by a second person, tested where possible, and recorded with a rollback plan. Emergency changes are recorded and reviewed the next working day.', 'تُطلب التغييرات على أنظمة الإنتاج وأجهزة الشبكة، ويُقيَّم خطرها، ويعتمدها شخص ثانٍ، وتُختبر متى أمكن، وتُوثَّق مع خطة للتراجع. وتُوثَّق التغييرات الطارئة وتُراجَع في يوم العمل التالي.'),
      S('Vulnerabilities', 'الثغرات', 'Systems are scanned for vulnerabilities at least monthly and internet-facing systems are penetration-tested at least every year and after major changes.', 'تُفحص الأنظمة بحثاً عن الثغرات شهرياً على الأقل، وتُجرى اختبارات الاختراق للأنظمة المتصلة بالإنترنت سنوياً على الأقل وبعد التغييرات الجوهرية.'),
      S('Patching', 'التحديثات', 'Critical security patches are applied within {patch_critical_days} days, others within the patch schedule; systems that cannot be patched are isolated and recorded as an exception.', 'تُطبق التحديثات الأمنية الحرجة خلال {patch_critical_days} يوماً، والتحديثات الأخرى وفق جدول التحديثات، وتُعزل الأنظمة التي يتعذر تحديثها وتُسجَّل كاستثناء.'),
      S('Configuration', 'الإعدادات', 'Systems and network devices follow an approved hardening baseline; their configurations are backed up and compared to it regularly.', 'تتبع الأنظمة وأجهزة الشبكة معيار تحصين معتمداً، وتُنسخ إعداداتها احتياطياً وتُقارن به بصفة دورية.'),
    ].concat(COMMON_END) },
  { id: 'network', owner: 'ciso', title: { en: 'Network and Firewall Security Policy', ar: 'سياسة أمن الشبكات وجدران الحماية' },
    refs: { nca: ['2-5'], iso: ['8.20', '8.21', '8.22'], pdpl: [], ndmo: [], aramco: 'Network security' },
    sections: [
      S('Segmentation', 'تقسيم الشبكة', 'The network is divided into zones - users, servers, management, guests, CCTV / building systems and project sites - and traffic between zones passes through a firewall.', 'تُقسَّم الشبكة إلى مناطق - المستخدمون، والخوادم، والإدارة، والضيوف، وكاميرات المراقبة وأنظمة المباني، ومواقع المشاريع - وتمر الحركة بين المناطق عبر جدار حماية.'),
      S('Firewall rules', 'قواعد جدار الحماية', 'Rules allow only named sources, destinations and services; any-to-any rules are not allowed; every rule has an owner and a reason, logs its traffic, and is reviewed every six months. Unused rules are removed.', 'لا تسمح القواعد إلا بمصادر ووجهات وخدمات محددة، ولا يُسمح بالقواعد المفتوحة من أي مصدر إلى أي وجهة، ولكل قاعدة مالك ومبرر، وتُسجِّل حركتها، وتُراجَع كل ستة أشهر، وتُحذف القواعد غير المستخدمة.'),
      S('Management', 'الإدارة', 'Network devices are managed only from the management network over encrypted protocols, with named administrator accounts and multi-factor authentication; Telnet, HTTP and SNMP v1/v2c are disabled.', 'لا تُدار أجهزة الشبكة إلا من شبكة الإدارة وعبر بروتوكولات مشفرة، وبحسابات إدارية بأسماء أصحابها مع التحقق متعدد العوامل، وتُعطَّل بروتوكولات Telnet وHTTP وSNMP الإصدارين الأول والثاني.'),
      S('Sites and remote connections', 'المواقع والاتصالات البعيدة', 'Branches and project sites connect over encrypted VPN tunnels to head office; internet access from sites passes the same security inspection as head office.', 'تتصل الفروع ومواقع المشاريع بالمقر الرئيسي عبر أنفاق VPN مشفرة، ويمر الوصول إلى الإنترنت من المواقع بنفس الفحص الأمني المطبق في المقر الرئيسي.'),
    ].concat(COMMON_END) },
  { id: 'sites', owner: 'ops', title: { en: 'Project Site and Field Operations Security Policy', ar: 'سياسة أمن مواقع المشاريع والعمليات الميدانية' },
    refs: { nca: ['2-14', '2-6', '5-1'], iso: ['7.1', '7.2', '7.4', '7.9', '8.1'], pdpl: ['19'], ndmo: [], aramco: 'Physical and site security' },
    sections: [
      S('Site set-up', 'تجهيز الموقع', 'Before a project site starts, IT and the site manager agree the network connection, the devices, who may use them and where equipment is kept. Network and server equipment is in a locked room or cabinet.', 'قبل بدء أي موقع مشروع، يتفق فريق تقنية المعلومات ومدير الموقع على اتصال الشبكة والأجهزة ومن يحق له استخدامها ومكان حفظ المعدات. وتوضع معدات الشبكة والخوادم في غرفة أو خزانة مقفلة.'),
      S('Shared and field devices', 'الأجهزة المشتركة والميدانية', 'Shared site PCs and tablets use named sign-in where possible, are enrolled in device management and the asset register, and are checked at every site handover.', 'تُستخدم أجهزة الحاسب والأجهزة اللوحية المشتركة في الموقع بتسجيل دخول باسم المستخدم متى أمكن، وتُسجَّل في نظام إدارة الأجهزة وسجل الأصول، وتُفحص عند كل تسليم للموقع.'),
      S('Client operational systems', 'الأنظمة التشغيلية للعميل', 'Staff working on client operational or industrial control systems follow the client\'s permit and access rules, never connect company devices to them without written approval, and never use removable media on them unless it has been scanned.', 'يلتزم الموظفون العاملون على الأنظمة التشغيلية أو أنظمة التحكم الصناعي للعميل بتصاريح العميل وقواعد الوصول لديه، ولا يوصلون أجهزة الشركة بها دون موافقة كتابية، ولا يستخدمون عليها وسائط تخزين إلا بعد فحصها.'),
      S('Closing a site', 'إغلاق الموقع', 'When a site closes, devices are returned to the asset register, accounts and VPN tunnels for the site are removed, and client data is returned or destroyed as the contract requires.', 'عند إغلاق الموقع تُعاد الأجهزة إلى سجل الأصول، وتُلغى الحسابات وأنفاق VPN الخاصة بالموقع، وتُعاد بيانات العميل أو تُتلف وفق ما يقتضيه العقد.'),
    ].concat(COMMON_END) },
];

function fill(text, o) { return String(text).replace(/\{(\w+)\}/g, (m, k) => (o[k] !== undefined && o[k] !== null ? String(o[k]) : m)); }
// a policy document in both languages, filled with the company's own values
function render(id, o) {
  const T = TEMPLATES.find((t) => t.id === id); if (!T) return null;
  const role = ROLES[o.owner_role || T.owner] || ROLES[T.owner];
  const v = Object.assign({}, DEFAULTS, o, { owner: role.en, owner_ar: role.ar });
  const sec = T.sections.map((s, i) => ({ n: i + 1, h: s.h, en: fill(s.p.en, v), ar: fill(s.p.ar, v) }));
  const title = { en: T.title.en, ar: T.title.ar };
  const head = (L) => (L === 'en' ? title.en + ' - ' + v.company + '\nOwner: ' + v.owner + ' · Review: every ' + v.review_months + ' months\n' : title.ar + ' - ' + v.company_ar + '\nالمالك: ' + v.owner_ar + ' · المراجعة: كل ' + v.review_months + ' شهراً\n');
  const text = (L) => head(L) + '\n' + sec.map((s) => s.n + '. ' + s.h[L] + '\n' + s[L]).join('\n\n');
  return { id: T.id, title, owner: { en: role.en, ar: role.ar }, refs: T.refs, sections: sec, text_en: text('en'), text_ar: text('ar') };
}
const list = () => TEMPLATES.map((t) => ({ id: t.id, title: t.title, owner: ROLES[t.owner], refs: t.refs, sections: t.sections.length }));
module.exports = { TEMPLATES, ROLES, DEFAULTS, render, list, fill };
