# Zyberon AI DLP — browser extension (Chrome / Edge)

This extension checks what people give AI apps such as ChatGPT, Claude, Gemini and Copilot. It runs **on the PC**:
the prompt or file is read and classified in the browser, and only metadata reaches the SIEM. That metadata is the app,
the data classes and counts, and what happened. No prompt text, file content or file name ever leaves the PC.

| Moment | What is checked |
| --- | --- |
| Paste into an AI page | The pasted text |
| Enter or Send | The message in the box |
| File chosen or dropped | Text files and Word / Excel / PowerPoint (`.docx`, `.xlsx`, `.pptx`), read locally |
| Opening a **blocked** app | The page is covered with a notice |

The classifier is `classify.js`. It uses the SIEM's personal-data rules with prompt thresholds:

- national ID / Iqama, mobile, e-mail
- IBAN, payment card (Luhn-checked)
- health terms
- private keys, API keys, passwords
- confidential labels (English and Arabic)
- the keywords an administrator lists

The decision comes from the **Shadow AI DLP register** in the SIEM, and the page shows it:

- **sanctioned:** only the data classes the register allows for that app go through.
- **tolerated / not reviewed:** any sensitive class is stopped.
- **blocked:** the app's page is covered.

Mode **warn** asks *Cancel / Send anyway* (both recorded). Mode **block** stops the action.

## Deploy (IT, once)

1. **SIEM:** on the Shadow AI DLP page, open the *Browser extension* tab and choose **Create token** (administrators).
   Copy the token; it is shown once.
2. **Package:** publish this folder as a private / unlisted item in the Chrome Web Store and Edge Add-ons, or pack it
   (`chrome --pack-extension=<folder>`) and host the `.crx` with an update manifest for managed Windows devices.
3. **Force-install** by policy, so people cannot remove it:
   - Chrome: `ExtensionInstallForcelist`
   - Edge: `ExtensionInstallForcelist`
4. **Configure** through the extension's managed policy (`managed_schema.json`). Keys:

   | Key | Value |
   | --- | --- |
   | `siem_url` | `https://<siem host>` |
   | `token` | The token from step 1 |
   | `device` | Optional: the computer name |

   - Chrome registry: `HKLM\Software\Policies\Google\Chrome\3rdparty\extensions\<extension id>\policy`
   - Edge registry: `HKLM\Software\Policies\Microsoft\Edge\3rdparty\extensions\<extension id>\policy`
   - Intune: configure the same keys with a custom OMA-URI / settings catalog.
5. **Close the gaps:** block other browsers and InPrivate / Incognito for the AI domains, and block developer tools for
   people who should not have them (`DeveloperToolsAvailability`).

The SIEM's nginx must pass `/ingest/ai-dlp/` to the engine, as it already does for `/ingest/`.

## What the SIEM receives

```json
{ "events": [ { "ts": 1763100000000, "app": "chatgpt", "host": "chatgpt.com", "action": "sent_after_warning",
  "channel": "paste", "kinds": { "national_id": 3 }, "classes": ["personal"], "user": "name@example.com",
  "ext_version": "1.0.0" } ] }
```

- `action` is one of: `blocked`, `warned` (cancelled), `sent_after_warning`, `page_blocked`, `heartbeat`.
- The SIEM refuses any other field. There is no field that can carry text.
- Events become DLP incidents (`dlp_vendor zyberon`), so they appear on the Shadow AI DLP page and in the DLP analysis.
- They are indicators, not proof: look at them with the person's manager and HR.

## Limits (said plainly)

- A person who can turn the extension off, or use an unmanaged browser or device, is not covered. Force-install it and
  block other browsers.
- Text typed into a page without a Send button the extension recognises is checked on Enter only.
- Images and scanned PDFs are not read.
- The ingest token is in the browser policy and can be read on the PC. It can only send AI DLP metadata (rate limited)
  and read the app list. Replace it on the SIEM page if it leaks.
