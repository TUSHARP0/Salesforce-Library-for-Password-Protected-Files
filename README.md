# 🔐 Salesforce Password-Protected Files Library

A lightweight Salesforce library, packaged as a **Static Resource**, that enables password-protected access to files within Salesforce. It can be integrated into **Lightning Web Components (LWC)**, **Aura Components**, or **Visualforce pages** to add an authentication layer before sensitive files can be viewed or downloaded.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Use Cases](#use-cases)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Compatibility](#compatibility)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

---

## 🧭 Overview

This library solves a common Salesforce challenge: **restricting access to files/documents** (contracts, reports, internal PDFs, etc.) without relying on external file-hosting services or complex sharing rule setups. It works entirely within Salesforce as a **Static Resource**, requiring no external dependencies or callouts.

Users are prompted for a password before the protected file is rendered, downloaded, or unlocked — making it ideal for sharing sensitive documents through Community/Experience Cloud sites, internal Lightning pages, or Visualforce-based portals.

---

## ✨ Features

- 🔒 **Password-gated file access** — prevents unauthorized viewing/downloading
- 📦 **Deployed as a Static Resource** — no external services or callouts required
- ⚡ **LWC / Aura / Visualforce compatible** — drop into any component type
- 🪶 **Lightweight** — minimal footprint, no heavy third-party dependencies
- 🔌 **Easy integration** — plug into existing Salesforce projects with minimal setup
- 🌐 **Works in Experience Cloud / Community sites** as well as internal orgs

---

## 💼 Use Cases

- Sharing confidential contracts or legal documents with external users
- Gating access to internal reports on a Community/Experience Cloud site
- Adding a lightweight security layer to files embedded in Visualforce pages
- Protecting downloadable assets (PDFs, spreadsheets, images) shared via Salesforce

---

## 📌 Example: Using Password-Protected Files with AI Prompts/Agents

### The Problem

When a password-protected file was sent directly to a prompt or an AI agent, the agent was **unable to extract the data** from the file — since it had no way to unlock or decrypt it. There was no Apache or third-party library integrated into the org to handle this, and pulling in an external library wasn't a viable option for this use case.

### The Solution

This custom library was built to solve that problem **natively within Salesforce**, without any external/third-party library integration:

1. The library is added to the org as a **Static Resource**.
2. It is imported and used inside a **Lightning Web Component (LWC)** JavaScript file.
3. The password-protected file is passed into the library to begin the decryption process.
4. The user is prompted to **enter the file password once**.
5. Once the correct password is entered, the library:
   - Opens the file
   - Extracts/decrypts the file's data
   - Creates a **temporary, non-password-protected copy** of the file
6. This temporary decrypted copy is what gets passed into the **prompt/agent** for data extraction/processing.
7. Once the prompt execution is complete, the **temporary file is deleted** automatically — the original password-protected file remains untouched and secure.

### Responsibility Split

| Layer | Responsibility |
|-------|-----------------|
| **Custom Library (Static Resource)** | Reading the password, opening the file, extracting/decrypting the file's data, generating the unprotected temporary copy |
| **Apex / LWC** | Handling temporary file **insertion** (creation/storage) and **deletion** (cleanup) logic after the prompt/agent execution completes |

### Example Flow

```javascript
import { LightningElement } from 'lwc';
import PASSWORD_PROTECT_LIB from '@salesforce/resourceUrl/passwordProtectLib';
import { loadScript } from 'lightning/platformResourceLoader';
import createTempFile from '@salesforce/apex/FileDecryptController.createTempFile';
import deleteTempFile from '@salesforce/apex/FileDecryptController.deleteTempFile';

export default class ProtectedFileAgentHandler extends LightningElement {

    async connectedCallback() {
        await loadScript(this, PASSWORD_PROTECT_LIB);
    }

    async handleUnlockAndExtract(protectedFile, enteredPassword) {
        // 1. Library decrypts the file using the entered password
        const decryptedData = await window.PasswordProtect.decrypt({
            file: protectedFile,
            password: enteredPassword
        });

        // 2. Apex creates a temporary, unprotected copy of the file
        const tempFileId = await createTempFile({ fileData: decryptedData });

        try {
            // 3. Temporary file is passed to the prompt/agent for processing
            await this.runPromptWithFile(tempFileId);
        } finally {
            // 4. Temporary file is deleted after execution, regardless of outcome
            await deleteTempFile({ fileId: tempFileId });
        }
    }

    async runPromptWithFile(tempFileId) {
        // Your prompt/agent execution logic goes here
    }
}
```

> ⚠️ **Security Note:** Since the temporary file is unprotected, ensure it is deleted immediately after the prompt/agent finishes execution — ideally using a `try/finally` block (as shown above) so cleanup happens even if the prompt execution fails or throws an error.

---

## ✅ Prerequisites

Before installing, ensure you have:

- A Salesforce org (Developer, Sandbox, or Production)
- Salesforce CLI (`sf` or `sfdx`) installed, if deploying via CLI
- API access enabled for your org
- Appropriate permissions to deploy Static Resources and Apex/LWC/Aura components

---

## 🚀 Installation

### Option 1: Deploy via Salesforce CLI

```bash
# Clone the repository
git clone https://github.com/<your-org>/<your-repo>.git
cd <your-repo>

# Authenticate to your org (if not already done)
sf org login web -a myOrgAlias

# Deploy the source to your org
sf project deploy start -o myOrgAlias
```

### Option 2: Deploy via Static Resource Upload (Manual)

1. Go to **Setup** → **Static Resources**
2. Click **New**
3. Upload the packaged `.zip` file from the `staticresources/` folder
4. Set the **Cache Control** as needed (`Public` or `Private`)

### Option 3: Package Install (if published as an unlocked/managed package)

```bash
sf package install --package <PACKAGE_ID> -o myOrgAlias
```

---

## 🛠️ Usage

### In a Lightning Web Component

```javascript
import { LightningElement } from 'lwc';
import PASSWORD_PROTECT_LIB from '@salesforce/resourceUrl/passwordProtectLib';
import { loadScript } from 'lightning/platformResourceLoader';

export default class ProtectedFileViewer extends LightningElement {
    async connectedCallback() {
        await loadScript(this, PASSWORD_PROTECT_LIB);
        // Initialize the library with your file reference and password logic
        window.PasswordProtect.init({
            fileUrl: '/resource/protectedFile',
            onUnlock: () => console.log('File unlocked successfully')
        });
    }
}
```

### In a Visualforce Page

```html
<apex:page>
    <apex:includeScript value="{!URLFOR($Resource.passwordProtectLib)}" />
    <div id="protected-file-container"></div>
    <script>
        PasswordProtect.init({
            fileUrl: '{!URLFOR($Resource.MyProtectedFile)}',
            containerId: 'protected-file-container'
        });
    </script>
</apex:page>
```

---

## ⚙️ Configuration

| Parameter    | Type       | Description                                      | Default    |
|--------------|-----------|---------------------------------------------------|------------|
| `fileUrl`    | `String`   | URL/reference of the file to protect              | *required* |
| `password`   | `String`   | Password required to unlock the file (or use a hashed value via Apex) | *required* |
| `containerId`| `String`   | DOM element ID to render the unlock UI into        | `null`     |
| `onUnlock`   | `Function` | Callback triggered after successful unlock         | `null`     |
| `maxAttempts`| `Number`   | Maximum allowed password attempts before lockout   | `5`        |

> 💡 **Security Tip:** Avoid hardcoding plain-text passwords in client-side code. Store hashed passwords in a Custom Metadata Type or Custom Setting, and validate via an Apex controller for stronger security.

---

## 📁 Project Structure

```
force-app/
└── main/
    └── default/
        ├── staticresources/
        │   └── passwordProtectLib.resource-meta.xml
        │   └── passwordProtectLib/
        │       ├── index.js
        │       └── styles.css
        ├── lwc/
        │   └── protectedFileViewer/
        ├── classes/
        │   └── PasswordValidatorController.cls
        └── pages/
            └── ProtectedFileDemo.page
```

---

## 🔗 Compatibility

| Platform             | Supported |
|-----------------------|:---------:|
| Lightning Web Components | ✅ |
| Aura Components        | ✅ |
| Visualforce Pages       | ✅ |
| Experience Cloud Sites  | ✅ |
| Salesforce Mobile App   | ⚠️ Partial (depends on component type) |

---

## ⚠️ Limitations

- This is a **client-side/UI-level** password gate, not a replacement for Salesforce sharing rules or field-level security — do not use it as the sole protection for highly sensitive data.
- For strong security, password validation should be handled server-side via an Apex controller rather than purely in JavaScript.
- Static Resources have a **5 MB per-file** limit (or higher depending on org edition) — large files may need to be chunked or hosted differently.

---

## 🩹 Troubleshooting

| Issue | Possible Cause | Fix |
|-------|-----------------|-----|
| Static Resource not loading | Incorrect `resourceUrl` reference | Verify the resource name matches exactly (case-sensitive) |
| Content-Type shown incorrectly | Salesforce auto-assigns MIME type on upload | Manually set `Content Type` in Static Resource detail page or `contentType` in `-meta.xml` |
| Password prompt not appearing | Script not loaded before DOM render | Ensure `loadScript`/`includeScript` completes before calling `init()` |
| Works in sandbox, fails in production | Static Resource not deployed/cached differently | Redeploy and clear org cache; verify Cache Control setting |

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Please ensure any new code follows existing formatting conventions and includes relevant tests where applicable.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — feel free to use, modify, and distribute with attribution.

---

## 💬 Support

For issues, questions, or feature requests, please [open an issue](../../issues) in this repository, or reach out to the maintainer team.

---

*Built for Salesforce developers who need a simple, dependency-free way to add password protection to shared files.*
