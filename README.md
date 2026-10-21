# S/MIME Secure Email – Virtual Laboratory

An interactive, web-based Virtual Laboratory simulation for college cryptography coursework demonstrating hybrid cryptography, digital signatures, and message integrity verification.

## Project Details
- **Project Title:** S/MIME Secure Email – Virtual Laboratory
- **Assignment Topic:** Implement S/MIME Secure Email (Simulation)
- **Team Members:**
  - Mohammad Zeeshan (USN: 4MW23CS072)
  - Mohd Arman (USN: 4MW23CS075)

## Features
- **100% Client-Side Web Crypto API**: Real RSA-2048, RSA-PSS signatures, SHA-256 hashing, AES-256-GCM symmetric encryption, and RSA-OAEP session key protection.
- **Python Code Logic Conversion**: Transposes the Python cryptography hazmat logic directly into standard browser JavaScript.
- **Interactive Visual Flow**: Follows each step of S/MIME operations visually and updates live statuses.
- **Tamper Demonstration**: Modify message content in transit to demonstrate actual mathematical verification failure.
- **Viva Voce Prep**: Comprehensive expandable Q&A covering core concepts.

## Local Setup & Running
```bash
# 1. Install dependencies
npm install

# 2. Run local development server
npm run dev

# 3. Build for production
npm run build
```

## Netlify Deployment
- **Build command:** `npm run build`
- **Publish directory:** `dist`
- **Environment variables:** None required (fully static client-side application).
