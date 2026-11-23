from org_brand import fill as _org_fill
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Full first drafts of PDPL policies (PDPL -> Policies). "Start a draft" on a policy with a text here creates its GRC draft
with this text as the body, instead of the outline alone. A DRAFT for the DPO and Legal to complete: every [bracketed] item is
an open question for the organisation, not a fact. It is approved only on GRC Policies, by an administrator who did not write or
change it (engine/grc.js draftStatus) - this file never makes a policy approved.

Written with the PDPL (Royal Decree M/19, amended by M/148), its Implementing Regulation (IR) and the Regulation on Personal
Data Transfer outside the Kingdom. Article references are to those texts; Legal confirms them before approval."""

PP01 = _org_fill("""**Draft 0.1 for the Data Protection Officer and Legal to complete. Bracketed items are open questions for {{org.short}} - nothing in brackets is a fact yet.**

## 1. Document control

| Field | Value |
| --- | --- |
| Document ID | PP-01 |
| Title | Personal Data Protection Policy |
| Version | 0.1 (draft) |
| Owner | Data Protection Officer [name to be confirmed] |
| Prepared by | [DPO / Legal] |
| Approver | [Board of Directors or the Board-delegated committee] |
| Effective date | On approval |
| Review cycle | Annual, and on any change to the PDPL, its Implementing Regulations, SDAIA guidance or the company's processing |
| Classification | Internal |
| Legal basis | Personal Data Protection Law (Royal Decree M/19, 1443H, amended by M/148, 1444H), its Implementing Regulation and the Regulation on Personal Data Transfer outside the Kingdom |
| Related frameworks | SAMA Cyber Security Framework, NCA ECC, NDMO Data Management and Personal Data Protection Standards, Insurance Authority and CHI requirements |

Open question: confirm whether the Board approves this policy directly or through a committee it has delegated to.

## 2. Purpose and scope

{{org.name}} processes personal data only lawfully, for stated purposes, and with protection proportionate to its sensitivity, as the PDPL requires. This policy sets the rules every employee, system and service provider follows to meet that requirement.

**Applies to**

- All personal data the company processes, in any form: databases, applications, e-mail, file shares, cloud services, paper and recordings.
- All data subjects: policyholders, applicants, insured members and their dependants, claimants and third parties to a claim, beneficiaries, brokers' and agents' contacts, employees, job applicants, contractors, visitors and website users.
- All business lines: [motor, medical, property and casualty, protection and savings - confirm the list].
- All employees, contractors, and processors acting for the company, inside and outside the Kingdom.
- Data of deceased persons where it can identify them or a member of their family (PDPL Art. 2).

**Out of scope**: data that has been anonymised so that no one can be identified (it is no longer personal data). Pseudonymised data stays in scope.

Where a stricter sector rule applies (Insurance Authority, Council of Health Insurance, SAMA, NCA), the stricter rule is followed.

## 3. Definitions

Terms carry the meaning in PDPL Art. 1 and Implementing Regulation (IR) Art. 1.

| Term | Meaning in this policy |
| --- | --- |
| Personal data | Any data that identifies a person or can identify them, directly or indirectly: name, national ID / Iqama, address, phone, policy, claim or customer number, bank details, photographs, voice recordings |
| Sensitive data | Racial or ethnic origin; religious, intellectual or political belief; security and criminal records; biometric or genetic data used for identification; health data; data showing that one or both parents are unknown |
| Health data | Any data on a person's physical, mental or psychological health, or on health services they received - including diagnoses, medical claims, pre-approvals and medical underwriting data |
| Credit data | Data on a request for, or receipt of, financing, and on the ability to repay - including premium financing and payment history where it shows creditworthiness |
| Processing | Any operation on personal data: collecting, recording, storing, using, disclosing, transferring, linking, blocking, erasing or destroying it |
| Controller | {{org.short}}, which decides the purpose and means of processing |
| Processor | A party that processes personal data on {{org.short}}'s behalf (for example a TPA, a cloud provider, a call centre, a printing house) |
| Data subject | The person the data is about |
| Personal data breach | Any incident that leads to unauthorised disclosure, destruction or access to personal data, deliberate or accidental |
| Explicit consent | Direct, unambiguous consent the company can prove |
| Anonymisation | Removing identifiers so that the person can never be identified again |
| Pseudonymisation | Replacing identifiers with codes, with the key kept separately; still personal data |
| DPO | The Data Protection Officer appointed under IR Art. 32 |

## 4. Processing principles

Every processing activity meets all seven principles; the business owner of the activity is accountable for showing it does.

1. **Lawful basis** - each activity has a recorded legal basis before it starts (section 5).
2. **Purpose limitation** - data is collected for a specific, stated purpose and not used for an unrelated one without a new legal basis (PDPL Arts. 10-11).
3. **Minimisation** - only the data necessary for the purpose is collected; each field on a form or screen maps to a purpose in the Record of Processing Activities (RoPA).
4. **Accuracy** - data is kept correct, complete and up to date; inaccurate data that could harm a person is not processed until corrected (Art. 17, IR Art. 22).
5. **Storage limitation** - data is kept no longer than the retention schedule allows, then destroyed or anonymised (section 10).
6. **Security** - organisational, administrative and technical measures protect data against loss, misuse and unauthorised access (section 9).
7. **Accountability** - every activity is recorded in the RoPA, and the evidence of compliance is kept and can be shown to SDAIA on request (IR Art. 33).

No new system, product, campaign or vendor that processes personal data goes live until the privacy-by-design review on PDPL -> Governance is completed.

## 5. Legal bases, consent and notices

The company processes personal data only on one of the legal bases below, recorded per activity in the RoPA (PDPL Arts. 5-6, IR Arts. 11-16).

| Legal basis | Typical use at an insurer | Conditions |
| --- | --- | --- |
| Consent | Marketing, optional services, voluntary surveys | Freely given, specific, informed, recorded with time and method; separate consent per purpose |
| Explicit consent | Health data outside what a law or contract requires, credit data, solely automated decisions | Direct and provable; never a condition of a service unless the service needs that data |
| Required by law or prior agreement | Issuing and servicing a policy, handling a claim, regulatory reporting, AML/CTF checks | The law or the contract named in the RoPA |
| Actual interest of the data subject | Contacting a beneficiary when the policyholder cannot be reached | Contact with the person is impossible or difficult |
| Legitimate interest | Fraud detection, network and information security | Private entity only; no sensitive data; a written legitimate-interest assessment approved by the DPO before processing starts (IR Art. 16) |

**Consent** is collected through the consent ledger (PDPL -> Consent), so each grant and withdrawal carries the notice version, time and channel. Withdrawing is at least as easy as giving consent; processing on that basis stops without undue delay, and parties the data was disclosed to are told (IR Art. 12).

**Privacy notice** - before or at collection, the person is told the legal basis and purpose, which fields are mandatory, who collects the data and how to contact them, who it is disclosed to, whether it leaves the Kingdom, the consequences of not providing it, and their rights (PDPL Arts. 12-13). The public notice is PP-02.

## 6. Sensitive, health and credit data

Health data is the company's largest body of sensitive data (medical insurance, medical claims, underwriting), so it carries the strictest controls.

- **Need to know** - access to health and claims data is limited to named roles, with tiered access levels; duties are split so no single person handles a medical case end to end where avoidable (IR Art. 26).
- **Logged access** - the claims, medical and fraud systems record who opened which record; the DPO reviews unusual access monthly (PDPL -> Sensitive Access).
- **Sector rules** - the Council of Health Insurance, Insurance Authority and SAMA requirements for health and insurance data are applied alongside this policy.
- **No legitimate interest, no direct marketing** - sensitive data is never processed on legitimate interest and never used for marketing.
- **DPIA first** - any new or changed processing of sensitive data, profiling, fraud scoring or automated underwriting needs an approved DPIA before it starts (section 9).
- **Credit data** - processed only with the person's consent and under SAMA requirements and the Credit Information Law; the person is told of any request to disclose it (PDPL Art. 24, IR Art. 27).
- **Minimum in documents** - diagnosis and treatment details are kept out of e-mail subjects, general correspondence and reports that do not need them.

Open question: confirm which roles may see full medical records versus claim summaries.

## 7. Data subject rights

Every request is answered within 30 days of receipt; the period may be extended by up to 30 more days only in exceptional cases, with the person told in advance and why (IR Art. 6).

| Right | What the company does | Reference |
| --- | --- | --- |
| To be informed | Gives the privacy notice before or at collection | PDPL Arts. 4, 12-13 |
| Access | Confirms what data it holds and lets the person see it | Art. 4; IR Art. 4 |
| Copy | Provides a copy in a clear, readable, commonly used electronic format | Art. 4; IR Art. 5 |
| Correction | Corrects, completes or updates the data, then tells everyone it was disclosed to | Arts. 4, 17; IR Art. 22 |
| Destruction | Destroys data no longer needed for its purpose, unless a law, contract or legal hold requires keeping it | Arts. 4, 18 |
| Withdraw consent | Stops processing on that consent without undue delay | IR Art. 12 |

**How a request is handled**

1. Received through any channel - branch, call centre, e-mail, web form - and logged on PDPL -> DSAR the same working day, including oral requests.
2. Identity verified before any data is released; supporting documents are destroyed after verification.
3. Systems holding the person's data are found through the data catalog and the tasks sent to their owners.
4. The response is reviewed by the DPO's team and sent; the request record keeps what was done and when.

A request may be refused only if it is repetitive, manifestly unfounded or needs disproportionate effort, or a legal exception applies; the person is told the reason. Requests for a person who lacks legal capacity are handled through their legal guardian.

## 8. Disclosure, processors, reinsurers and transfers outside the Kingdom

**Disclosure** to another party happens only on a basis in PDPL Art. 15 - consent, a legal requirement, a public authority's request for security or judicial purposes, a vital interest, or legitimate interest without sensitive data - and never where Art. 15 forbids it. Requests from public authorities are recorded with what was asked and what was given.

**Processors** (TPAs, medical networks' portals, call centres, cloud and IT providers, printing and archiving) are engaged only after a vendor privacy assessment (PDPL -> Processors) and under a written agreement that sets out:

- the purpose, data categories and duration of processing;
- notification of any breach to the company without undue delay;
- whether the processor is subject to laws of another country;
- sub-processors named, and prior approval for new ones;
- return or destruction of the data at the end of the contract, and the company's right to audit.

A processor that acts outside the company's instructions becomes a controller and is directly liable (PDPL Art. 8, IR Art. 17).

**Transfers outside the Kingdom** - including to reinsurers, a group entity, or a cloud region abroad - are made only for a purpose allowed by PDPL Art. 29 and under one of:

1. an adequacy decision published by SDAIA;
2. appropriate safeguards - SDAIA standard contractual clauses, binding common rules, a certification or a binding code of conduct;
3. an exemption in the Transfer Regulation (for example, performing a contract with the person).

A transfer risk assessment is completed before transfers under safeguards or an exemption, and before any continuous or large-scale transfer of sensitive data (PDPL -> Transfers). Transfers stop at once if they threaten national security or the safeguards no longer hold.

Open question: list the current reinsurers, TPAs and cloud services that receive personal data, and where each processes it.

## 9. Security, breaches and impact assessments

**Security** - personal data is protected under the company's cyber security policies and the NCA Essential Cybersecurity Controls and SAMA Cyber Security Framework (PDPL Art. 19, IR Art. 23). Systems holding personal data are, at minimum: in the asset register with a named owner, classified Confidential or above, on supported software, protected against malware, patched, backed up, scanned for vulnerabilities and logging to the SIEM. PDPL -> Control Monitor tests these every six hours.

**Breach notification** - anyone who suspects a personal data breach reports it at once to the IT Service Desk or the DPO.

1. The incident response team contains it and assesses whether it may harm data subjects.
2. If it may, the DPO notifies SDAIA within 72 hours of the company becoming aware, with the description, data categories, approximate number of people, risks, measures taken and contact details. Information not yet available is sent with the reason for the delay (IR Art. 24).
3. Affected people are told without undue delay, in plain language, with what happened and what they can do to protect themselves.
4. The Insurance Authority, SAMA, NCA and the Council of Health Insurance are notified where their own rules require.
5. Every breach, notified or not, is recorded on PDPL -> Breach with its decision and reasons.

**Data protection impact assessment (DPIA)** - required before processing that involves sensitive data; combining or linking personal data from two or more sources; continuous large-scale processing of people lacking legal capacity; continuous monitoring; new technology or solely automated decisions; or anything likely to cause serious harm to privacy (PDPL Art. 22, IR Art. 25). For the company this includes fraud scoring, automated underwriting, telematics and new medical or claims systems. If the DPIA finds unacceptable risk, processing does not start until the risk is reduced and the DPIA redone.

## 10. Retention, destruction and records

Personal data is destroyed or anonymised without undue delay once its purpose ends, unless a law or contract requires a set retention period or it relates to a pending case (PDPL Art. 18, IR Art. 19).

- **Retention schedule** - each data category and system has a period, its trigger and its legal reference, kept on PDPL -> Retention and owned by the system's data owner (detail in PP-06).
- **Destruction** - planned per system and cut-off date, approved by a second person, then confirmed done; the record of what was destroyed and when is kept (PDPL -> Retention).
- **Legal holds** - data under a regulatory inquiry, litigation or claim dispute is placed on hold and excluded from destruction until the hold is released by Legal.
- **Records of processing (RoPA)** - each activity is recorded with its purpose, legal basis, data categories, data subjects, recipients, transfers abroad, retention and security measures. Records are kept for as long as the processing runs plus 5 years, and are available to SDAIA on request (IR Art. 33). Department data stewards update the RoPA through the yearly campaign and whenever a process changes.

Open question: confirm the retention periods for policy, claims, medical and employee records against the Insurance Authority and other applicable rules.

## 11. Roles and responsibilities

The company appoints a DPO because its core activities include processing sensitive (health) data at scale (IR Art. 32).

| Role | Responsible for |
| --- | --- |
| Board of Directors | Approving this policy; overseeing PDPL compliance through regular reports |
| Privacy committee [chair and members to be named: Legal, IT, Cyber Security, Compliance, HR, Operations] | Steering the programme, deciding risk acceptances and exceptions, reviewing breaches and DPIAs |
| Data Protection Officer | Point of contact for SDAIA; overseeing DPIAs, breach notification, data subject requests and complaints; keeping the RoPA current; monitoring compliance and reporting to the Board |
| Data owners (heads of business lines and functions) | The lawful basis, purpose, retention and access of the processing in their area |
| Department data stewards | Keeping their department's RoPA entries current; first point for privacy questions in the department |
| CISO and IT | Security controls on systems holding personal data; incident response; technical support for requests and destruction |
| Compliance | Mapping PDPL obligations to sector regulation; regulator correspondence with the DPO |
| Procurement and Legal | Processor and transfer agreements; vendor privacy assessments before contract |
| HR | Employee personal data; privacy clauses in contracts; disciplinary process for violations |
| All employees and contractors | Following this policy; completing training; reporting suspected breaches immediately |

Open question: name the DPO and their deputy, and confirm the DPO's reporting line and independence.

## 12. Marketing, training, monitoring and enforcement

**Marketing** - direct marketing and promotional messages use non-sensitive data only, collected from the person, with their consent. Each message names the company and offers a free opt-out at least as easy as opting in; an opt-out is honoured without undue delay (PDPL Arts. 25-26, IR Arts. 28-29).

**Training and acknowledgement** - every employee completes PDPL awareness training on joining and every year after; staff in claims, medical, customer service, HR and IT complete role-specific training. Every employee acknowledges this policy on joining and on each new version (PDPL -> Control Monitor, acknowledgement campaigns).

**Monitoring** - compliance is checked continuously by the Control Monitor, yearly by the PDPL self-assessment approved by the DPO, and by Internal Audit in its plan. Gaps become remediation actions in the GRC register with an owner and a due date.

**Exceptions** - an exception to this policy is requested in writing with the reason, the compensating control and an end date of no more than 12 months, and approved by the privacy committee. It cannot set aside a requirement of the law.

**Violations** - breaching this policy may lead to disciplinary action under the company's HR rules, and may expose the company and individuals to the penalties in the PDPL (Arts. 35-36). Disclosing or publishing sensitive data with intent to harm the person or for personal benefit is a criminal offence under Art. 35.

## 13. Related documents and approval

**Related company documents** (PDPL -> Policies)

- PP-02 Privacy Notice
- PP-03 Data Classification & Handling Policy
- PP-04 Consent Management Procedure
- PP-05 Data Subject Rights Procedure
- PP-06 Data Retention & Disposal Policy
- PP-07 Data Breach Notification Policy
- PP-08 Data Protection Impact Assessment Procedure
- PP-09 Cross-Border Data Transfer & Residency Policy
- IT and cyber security policies in the GRC register, in particular Regulatory Compliance (IT-RC-001), Staff Competence & Training (IT-SCT-001) and IT Incident Management (IT-OPS-008)

**External references**

- Personal Data Protection Law, Royal Decree M/19 (1443H), amended by Royal Decree M/148 (1444H)
- Implementing Regulation of the PDPL (SDAIA)
- Regulation on Personal Data Transfer outside the Kingdom (SDAIA)
- NCA Essential Cybersecurity Controls; SAMA Cyber Security Framework; NDMO Data Management and Personal Data Protection Standards
- Insurance Authority and Council of Health Insurance requirements applicable to the company [list to be confirmed by Compliance]

**Approval**

| Step | Name | Role | Date |
| --- | --- | --- | --- |
| Prepared | | Data Protection Officer | |
| Reviewed | | Legal / Compliance | |
| Approved | | [Board or delegated committee] | |

In the platform, approval is recorded when a second administrator approves the PP-01 draft on GRC Policies; the document's author cannot approve it.
""")

PP02 = _org_fill("""**Draft notice for customers, insured members, claimants and website visitors, in plain language for the website, the app and branches. It must also be published in Arabic, and the two texts must match. Bracketed items are for {{org.short}} to confirm.**

## 1. Who we are

{{org.name}} ("{{org.short}}", "we") decides how and why your personal data is used, so we are its controller under the Saudi Personal Data Protection Law (PDPL).

| | |
| --- | --- |
| Company | {{org.name}} [commercial registration no. to be confirmed] |
| Address | [head office address, Riyadh] |
| Customer care | [phone] - [e-mail] - any branch |
| Data Protection Officer | [name or role] - [dpo@ e-mail address] |

You can contact our Data Protection Officer about anything in this notice, including how to use your rights.

## 2. What personal data we collect

We collect only what we need for the purpose we tell you about.

| If you are | We may collect |
| --- | --- |
| A policyholder or applicant | Name, national ID or Iqama, date of birth, nationality, gender, contact details, address, employer, bank or payment details, details of what is insured (vehicle, property, driving history, prior claims) |
| An insured member or dependant (medical insurance) | Identity and contact details, relationship to the policyholder, and health information needed for cover and claims |
| A claimant, injured party or witness | Identity and contact details, what happened, photographs, police or Najm reports, medical reports where an injury is involved, bank details for payment |
| A beneficiary | Identity, contact and bank details |
| A website or app user | Log-in details, device and browser data, IP address, pages used, and what you tell us through forms or chat |
| A caller or visitor | Call recordings [confirm] and CCTV at our branches [confirm] |

We do not ask for more than a form or process needs. Fields marked as optional can be left empty.

## 3. Why we use it and on what basis

We use your data only for the purposes below, each on a basis the PDPL allows.

| Purpose | Legal basis |
| --- | --- |
| Quoting, underwriting and issuing your policy; renewals and changes | Your insurance contract |
| Collecting premiums and paying claims | Your insurance contract |
| Handling claims, including those of third parties | Your insurance contract and the law |
| Meeting legal and regulatory duties: Insurance Authority, Council of Health Insurance, SAMA, anti-money-laundering, tax (ZATCA), compulsory motor insurance | The law |
| Detecting and preventing fraud | The law and our legitimate interest (never using sensitive data on this basis) |
| Keeping our systems and your data secure | Our legitimate interest and the law |
| Answering your questions and complaints | Your request and the law |
| Telling you about our products and offers | Your consent - you can withdraw it at any time |
| Surveys and service improvement | Your consent, or our legitimate interest using non-sensitive data |

If we want to use your data for a new purpose that does not fit one of these, we will tell you first and ask for your consent where the law requires it.

## 4. Health and other sensitive data

For medical insurance and some claims we need health information, such as diagnoses, treatment and medical reports. The law treats it as sensitive, and we give it extra protection.

- We use it only to provide your cover, approve treatment and pay claims, and to meet health-insurance rules.
- Only staff and service providers who need it for those tasks can see it, and every access is recorded.
- We never use it for marketing, and never on the basis of our legitimate interest.
- Where the law requires your explicit consent, we ask for it separately and record it.

We do not collect other sensitive data, such as religious belief or criminal records, unless a law requires it. [Confirm: any case where such data is needed, for example criminal records for certain motor claims.]

## 5. Where your data comes from, and if you do not give it

Most of your data comes from you. We also receive it from:

- the policyholder, when you are insured under someone else's policy (for example your employer's group medical plan);
- brokers and agents who arrange your insurance;
- hospitals, clinics and pharmacies in our medical network, when you receive treatment;
- official sources we are permitted to use, such as [Yakeen / Absher identity verification, Najm and traffic records, SAMA's or the Insurance Authority's systems - confirm the list];
- other insurers, loss adjusters and claim parties during a claim.

**If you do not provide data** we mark as required, we may not be able to issue your policy, renew it or pay a claim. Data marked optional is never a condition of the service.

## 6. Who we share it with

We do not sell your personal data. We share it only when needed for the purposes above:

- **Service providers acting for us**, under contracts that bind them to protect it: third-party administrators for medical claims, our medical provider network, call centres, IT and cloud providers, printing and archiving firms.
- **Reinsurers**, who share the risk of your policy with us.
- **Brokers and agents** who arranged your insurance.
- **Loss adjusters, surveyors, lawyers and other insurers** involved in a claim.
- **Regulators and authorities** when the law requires: the Insurance Authority, the Council of Health Insurance, SAMA, ZATCA, courts, the police and other public authorities.

**Outside Saudi Arabia** - some reinsurers and service providers are abroad [confirm countries]. We transfer data outside the Kingdom only where the PDPL and SDAIA's Transfer Regulation allow it, and with the safeguards they require, such as SDAIA's standard contractual clauses. You can ask our Data Protection Officer which safeguards apply.

## 7. How long we keep it and how we protect it

We keep your data only as long as the purpose needs, plus any period the law requires, then we destroy it or make it anonymous.

| Records | Kept for |
| --- | --- |
| Policy records | [period] after the policy ends |
| Claims records, including medical claims | [period] after the claim is closed |
| Applications that did not become a policy | [period] |
| Call recordings | [period] |
| Marketing preferences | Until you withdraw consent, plus [period] as proof |

Records linked to a dispute, investigation or court case are kept until it is concluded.

We protect your data with technical and organisational measures that follow the National Cybersecurity Authority's controls and SAMA's cyber security requirements. These include access limited to those who need it, encryption, monitoring and staff training. If a breach is likely to harm you, we will tell you without undue delay and explain what you can do.

## 8. Your rights

Under the PDPL you have the right to:

- **be informed** of how your data is used - this notice;
- **access** the personal data we hold about you;
- **get a copy** of it in a clear, readable format;
- **correct** data that is wrong, incomplete or out of date;
- **ask us to destroy** data we no longer need, unless a law or your contract requires us to keep it;
- **withdraw your consent** at any time, where we rely on it. This does not affect what we did before you withdrew it.

**How to use them** - contact us at [privacy web form / e-mail], call [phone] or visit any branch. We will check your identity before releasing any data, and reply within 30 days. In exceptional cases we may need up to 30 more days; if so, we will tell you why before the first 30 days end. Using your rights is free of charge.

**Marketing** - you can stop marketing messages at any time with the opt-out link or reply in each message, or by contacting us.

**Complaints** - if you are not satisfied with our answer, contact our Data Protection Officer. You can also complain to the Saudi Data and Artificial Intelligence Authority (SDAIA).

## 9. Cookies and changes to this notice

**Cookies** - our website and app use cookies that are needed for them to work and stay secure. We use analytics or advertising cookies only if you agree, and you can change your choice at any time in [cookie settings]. [Confirm which analytics and advertising tools are used.]

**Changes** - we update this notice when our processing or the law changes. The date at the top shows the current version. If a change affects how we use your data in a significant way, we will tell you before it takes effect.

*Last updated: [date] - Version [1.0]*

---

### Notes for the publisher (remove before publishing)

- Publish the Arabic version alongside this one; the two texts must match.
- Place it on the website footer, the app's sign-up and settings screens, every data-collection form (a short notice with a link), the call-centre script, and at branches.
- Record each published version in PDPL -> Consent as the notice version, so consents show which text the person saw.
- Before approval, fill every bracketed item and check this notice against the RoPA, so every purpose, recipient and transfer listed here is also recorded there, and the RoPA has nothing this notice leaves out.
- Approval route: PDPL -> Policies -> PP-02 -> submit; a second administrator approves on GRC Policies.
""")

TEXTS = {'PP-01': PP01, 'PP-02': PP02}


def text_of(pid):
    return TEXTS.get(pid)


def sections_of(text):
    """The '## ' headings - the draft's requirement list on GRC Policies, so a reviewer sees the structure at a glance."""
    return [ln[3:].strip() for ln in (text or '').splitlines() if ln.startswith('## ')]
