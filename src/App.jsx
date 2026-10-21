import React, { useState } from 'react';
import './App.css';
import {
  generateRSAKeyPair,
  computeSHA256,
  createSignature,
  verifySignature,
  encryptMessageAES,
  encryptAESKeyWithRSA,
  decryptAESKeyWithRSA,
  decryptMessageAES,
  bufferToHex,
} from './crypto';

export default function App() {
  // Input fields (Live Demonstration)
  const [senderEmail, setSenderEmail] = useState('alice@gmail.com');
  const [receiverEmail, setReceiverEmail] = useState('bob@gmail.com');
  const [message, setMessage] = useState('Hello Bob, this is a secure email.');

  // Cryptographic Keys State
  const [senderKeys, setSenderKeys] = useState(null); // RSA-PSS 2048
  const [receiverKeys, setReceiverKeys] = useState(null); // RSA-OAEP 2048

  // Artifacts
  const [messageHash, setMessageHash] = useState('');
  const [signatureRaw, setSignatureRaw] = useState(null);
  const [signatureHex, setSignatureHex] = useState('');
  const [aesSessionKey, setAesSessionKey] = useState(null);
  const [aesIv, setAesIv] = useState(null);
  const [encryptedPayload, setEncryptedPayload] = useState(null);
  const [encryptedAesKey, setEncryptedAesKey] = useState(null);

  // Decryption & Verification Results
  const [decryptedMessage, setDecryptedMessage] = useState('');
  const [isDecrypted, setIsDecrypted] = useState(false);
  const [isSignatureValid, setIsSignatureValid] = useState(null);

  // Tamper / Security Test
  const [isTampered, setIsTampered] = useState(false);
  const [feedback, setFeedback] = useState(null);
  const [feedbackType, setFeedbackType] = useState('info');

  // STEP 1: GENERATE KEYS
  const handleGenerateKeys = async () => {
    try {
      setFeedback(null);
      const sKeys = await generateRSAKeyPair('sign');
      const rKeys = await generateRSAKeyPair('encrypt');

      setSenderKeys(sKeys);
      setReceiverKeys(rKeys);
      setFeedbackType('info');
      setFeedback('✓ Step 1 Complete: Generated RSA-2048 key pairs (Alice: RSA-PSS for signing, Bob: RSA-OAEP for encryption).');
    } catch (err) {
      console.error(err);
      setFeedbackType('error');
      setFeedback('Error generating keys: ' + err.message);
    }
  };

  // STEP 2: CREATE DIGITAL SIGNATURE
  const handleSignMessage = async () => {
    if (!senderKeys) {
      setFeedbackType('error');
      setFeedback('Please generate keys first (Step 1).');
      return;
    }
    if (!message.trim()) {
      setFeedbackType('error');
      setFeedback('Please enter an email message.');
      return;
    }
    try {
      setFeedback(null);
      const hash = await computeSHA256(message);
      setMessageHash(hash);

      const sigBuffer = await createSignature(message, senderKeys.privateKey);
      setSignatureRaw(sigBuffer);
      setSignatureHex(bufferToHex(sigBuffer));
      setFeedbackType('info');
      setFeedback('✓ Step 2 Complete: SHA-256 hash computed and signed with Alice\'s RSA-PSS Private Key.');
    } catch (err) {
      console.error(err);
      setFeedbackType('error');
      setFeedback('Error creating signature: ' + err.message);
    }
  };

  // STEP 3: ENCRYPT EMAIL
  const handleEncryptEmail = async () => {
    if (!signatureRaw) {
      setFeedbackType('error');
      setFeedback('Please create a digital signature first (Step 2).');
      return;
    }
    if (!receiverKeys) {
      setFeedbackType('error');
      setFeedback('Please generate keys first (Step 1).');
      return;
    }
    try {
      setFeedback(null);
      // Hybrid encryption: AES-256-GCM body + RSA-OAEP key wrapping
      const { rawAesKey, iv, encryptedBuffer } = await encryptMessageAES(message);
      setAesSessionKey(rawAesKey);
      setAesIv(iv);
      setEncryptedPayload(encryptedBuffer);

      const encKey = await encryptAESKeyWithRSA(rawAesKey, receiverKeys.publicKey);
      setEncryptedAesKey(encKey);

      setFeedbackType('info');
      setFeedback('✓ Step 3 Complete: Email encrypted with AES-256. AES session key encrypted with Bob\'s RSA-OAEP Public Key.');
    } catch (err) {
      console.error(err);
      setFeedbackType('error');
      setFeedback('Error encrypting email: ' + err.message);
    }
  };

  // STEP 4: DECRYPT & VERIFY
  const handleDecryptAndVerify = async () => {
    if (!encryptedPayload || !encryptedAesKey) {
      setFeedbackType('error');
      setFeedback('Please encrypt the email first (Step 3).');
      return;
    }
    try {
      setFeedback(null);
      // Unwrap AES key with Receiver's private RSA key
      const rawAesKey = await decryptAESKeyWithRSA(encryptedAesKey, receiverKeys.privateKey);

      // Decrypt AES ciphertext
      let plainText = await decryptMessageAES(rawAesKey, aesIv, encryptedPayload);

      // Tampering simulation
      if (isTampered) {
        plainText = 'Hello Bob, this is a hacked email.';
      }

      setDecryptedMessage(plainText);
      setIsDecrypted(true);

      // Real signature verification using Alice's public key
      const isValid = await verifySignature(plainText, signatureRaw, senderKeys.publicKey);
      setIsSignatureValid(isValid);

      if (isValid) {
        setFeedbackType('info');
        setFeedback('✓ Step 4 Complete: Email decrypted with Bob\'s private key & digital signature verified successfully! Integrity confirmed.');
      } else {
        setFeedbackType('error');
        setFeedback('✗ Verification Failed: Signature mismatch detected! The email content was altered after signing.');
      }
    } catch (err) {
      console.error(err);
      setFeedbackType('error');
      setFeedback('Error during decryption/verification: ' + err.message);
    }
  };

  // TAMPER MESSAGE (Set tampered text)
  const handleTamperMessage = () => {
    if (!encryptedPayload) {
      setFeedbackType('error');
      setFeedback('Please encrypt the email first before testing tampering.');
      return;
    }
    setIsTampered(true);
    // If already decrypted, re-run verification on the tampered message immediately
    if (isDecrypted) {
      const tamperedText = 'Hello Bob, this is a hacked email.';
      setDecryptedMessage(tamperedText);
      verifySignature(tamperedText, signatureRaw, senderKeys.publicKey).then(isValid => {
        setIsSignatureValid(isValid);
      });
    }
    setFeedbackType('error');
    setFeedback('⚠️ Message tampered in transit to: "Hello Bob, this is a hacked email." Click "4. Decrypt & Verify" to observe real cryptographic verification failure!');
  };

  // RESTORE ORIGINAL MESSAGE
  const handleRestoreMessage = () => {
    setIsTampered(false);
    if (isDecrypted && encryptedPayload && aesSessionKey) {
      decryptMessageAES(aesSessionKey, aesIv, encryptedPayload).then(originalText => {
        setDecryptedMessage(originalText);
        verifySignature(originalText, signatureRaw, senderKeys.publicKey).then(isValid => {
          setIsSignatureValid(isValid);
          setFeedbackType('info');
          setFeedback('✓ Original message restored. Digital signature re-verified successfully!');
        });
      });
    } else {
      setFeedbackType('info');
      setFeedback('✓ Tampering cancelled. Original message status restored.');
    }
  };

  // RESET
  const handleReset = () => {
    setSenderEmail('alice@gmail.com');
    setReceiverEmail('bob@gmail.com');
    setMessage('Hello Bob, this is a secure email.');
    setSenderKeys(null);
    setReceiverKeys(null);
    setMessageHash('');
    setSignatureRaw(null);
    setSignatureHex('');
    setAesSessionKey(null);
    setAesIv(null);
    setEncryptedPayload(null);
    setEncryptedAesKey(null);
    setDecryptedMessage('');
    setIsDecrypted(false);
    setIsSignatureValid(null);
    setIsTampered(false);
    setFeedback(null);
  };

  // Current active step calculation
  const getCurrentStep = () => {
    if (isDecrypted) return 4;
    if (encryptedPayload) return 3;
    if (signatureRaw) return 2;
    if (senderKeys) return 1;
    return 0;
  };

  const currentStep = getCurrentStep();

  return (
    <div className="page-wrapper">
      {/* 1. TOP NAVIGATION BAR */}
      <nav className="navbar">
        <div className="navbar-inner">
          <a href="#intro" className="navbar-logo">
            <div className="navbar-logo-icon">✉️</div>
            <div className="navbar-logo-text">
              S/MIME <span>LAB</span>
            </div>
          </a>

          <ul className="navbar-nav">
            <li><a href="#intro">Introduction</a></li>
            <li><a href="#objectives">Objectives</a></li>
            <li><a href="#theory">Theory</a></li>
            <li><a href="#simulation">Simulation</a></li>
            <li><a href="#demo">Live Demo</a></li>
            <li><a href="#security-test">Security Test</a></li>
            <li><a href="#results">Results</a></li>
            <li><a href="#conclusion">Conclusion</a></li>
          </ul>

          <div className="navbar-right">
            <span className="navbar-tag">ACADEMIC LAB</span>
          </div>
        </div>
      </nav>

      {/* HEADER / HERO BANNER */}
      <header className="hero-banner">
        <div className="container hero-container">
          <div className="badge-pink">College Cryptography Laboratory</div>
          <h1 className="hero-main-title">
            S/MIME SECURE EMAIL <span className="highlight-maroon">VIRTUAL LABORATORY</span>
          </h1>
          <p className="hero-subtext">
            Assignment Topic: <strong>Implement S/MIME Secure Email (Simulation)</strong>
          </p>

          {/* PROJECT TEAM CARD */}
          <div className="team-banner-card">
            <div className="team-banner-title">PROJECT TEAM</div>
            <div className="team-members">
              <div className="team-member">
                <span className="member-name">Mohammad Zeeshan</span>
                <span className="member-usn">USN: 4MW23CS072</span>
              </div>
              <div className="team-divider">•</div>
              <div className="team-member">
                <span className="member-name">Mohd Arman</span>
                <span className="member-usn">USN: 4MW23CS075</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* SECTION 1: INTRODUCTION */}
      <section id="intro" className="section">
        <div className="container">
          <div className="section-header">
            <div className="section-pill">SECTION 1</div>
            <h2 className="section-title">Introduction to S/MIME</h2>
            <p className="section-subtitle">
              Secure/Multipurpose Internet Mail Extensions (S/MIME) provides end-to-end security for electronic mail.
            </p>
          </div>

          <div className="intro-card">
            <p className="intro-text">
              Standard email protocol (SMTP) transmits messages in clear plaintext across mail transfer agents, leaving them vulnerable to eavesdropping, impersonation, and unauthorized modification. S/MIME solves this by combining <strong>asymmetric cryptography</strong> (for identity authentication and non-repudiation) with <strong>symmetric cryptography</strong> (for high-speed confidentiality).
            </p>

            {/* Visual Process Flow */}
            <div className="email-flow-visual">
              <div className="flow-step-box">
                <div className="flow-box-icon">📄</div>
                <div className="flow-box-title">PLAINTEXT EMAIL</div>
                <div className="flow-box-desc">Raw cleartext message vulnerable in transit</div>
              </div>

              <div className="flow-arrow-box">
                <span className="flow-arrow">➔</span>
                <span className="flow-label">S/MIME PROTOCOL</span>
              </div>

              <div className="flow-step-box active-flow">
                <div className="flow-box-icon">🔐</div>
                <div className="flow-box-title">S/MIME PROTECTION</div>
                <div className="flow-box-desc">Digitally signed &amp; hybrid encrypted</div>
              </div>

              <div className="flow-arrow-box">
                <span className="flow-arrow">➔</span>
                <span className="flow-label">DELIVERED</span>
              </div>

              <div className="flow-step-box">
                <div className="flow-box-icon">🛡️</div>
                <div className="flow-box-title">SECURE EMAIL</div>
                <div className="flow-box-desc">Confidentiality, Integrity &amp; Authenticity guaranteed</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 2: EXPERIMENTAL OBJECTIVES */}
      <section id="objectives" className="section section-soft">
        <div className="container">
          <div className="section-header">
            <div className="section-pill">SECTION 2</div>
            <h2 className="section-title">Experimental Objectives</h2>
            <p className="section-subtitle">Key learning outcomes and experimental goals of this virtual laboratory</p>
          </div>

          <div className="cards-grid-4">
            <div className="feature-card">
              <div className="card-badge-num">01</div>
              <div className="card-icon">📚</div>
              <h3 className="card-heading">Understand S/MIME</h3>
              <p className="card-body-text">
                Understand the fundamental principles of S/MIME secure email architecture and how hybrid cryptosystems work together.
              </p>
            </div>

            <div className="feature-card">
              <div className="card-badge-num">02</div>
              <div className="card-icon">🔑</div>
              <h3 className="card-heading">Generate Keys</h3>
              <p className="card-body-text">
                Generate sender RSA key pair for digital signing (RSA-PSS) and receiver RSA key pair for encryption (RSA-OAEP).
              </p>
            </div>

            <div className="feature-card">
              <div className="card-badge-num">03</div>
              <div className="card-icon">🔒</div>
              <h3 className="card-heading">Secure an Email</h3>
              <p className="card-body-text">
                Create a digital signature with SHA-256, encrypt the email body with AES-256, and wrap the session key with RSA.
              </p>
            </div>

            <div className="feature-card">
              <div className="card-badge-num">04</div>
              <div className="card-icon">🛡️</div>
              <h3 className="card-heading">Detect Tampering</h3>
              <p className="card-body-text">
                Simulate an active adversary altering the ciphertext in transit and prove that the receiver's digital signature verification fails.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 3: THEORETICAL BACKGROUND */}
      <section id="theory" className="section">
        <div className="container">
          <div className="section-header">
            <div className="section-pill">SECTION 3</div>
            <h2 className="section-title">Theoretical Background</h2>
            <p className="section-subtitle">Cryptographic mechanisms securing modern electronic mail</p>
          </div>

          <div className="cards-grid-4">
            <div className="feature-card">
              <div className="card-icon">✍️</div>
              <h3 className="card-heading">Digital Signature</h3>
              <p className="card-body-text">
                Alice hashes the plaintext with <strong>SHA-256</strong> and signs it using her <strong>RSA Private Key</strong> (RSA-PSS). This provides sender authentication and non-repudiation.
              </p>
            </div>

            <div className="feature-card">
              <div className="card-icon">⚡</div>
              <h3 className="card-heading">AES Encryption</h3>
              <p className="card-body-text">
                The email body is encrypted using <strong>AES-256-GCM</strong> with a random one-time symmetric session key. Symmetric encryption provides high-speed message confidentiality.
              </p>
            </div>

            <div className="feature-card">
              <div className="card-icon">🛡️</div>
              <h3 className="card-heading">RSA Key Protection</h3>
              <p className="card-body-text">
                The symmetric AES key is encrypted using Bob's <strong>RSA Public Key</strong> (RSA-OAEP). Only Bob holding his matching RSA Private Key can recover the AES session key.
              </p>
            </div>

            <div className="feature-card highlight-card">
              <div className="card-icon">🔄</div>
              <h3 className="card-heading">Hybrid Encryption</h3>
              <p className="card-body-text font-semibold">
                "AES encrypts the message. RSA protects the AES key."
              </p>
              <p className="card-body-text" style={{ marginTop: '0.4rem', fontSize: '0.82rem' }}>
                Combines the computational speed of symmetric ciphers with the flexible key exchange of asymmetric cryptography.
              </p>
            </div>
          </div>

          {/* Browser Implementation Note */}
          <div className="note-card">
            <span className="note-icon">ℹ️</span>
            <div>
              <strong>Browser Crypto Note:</strong> Standard Web Crypto API natively supports <code>AES-256-GCM</code> for symmetric authenticated encryption. The hybrid S/MIME architectural logic remains completely identical to standard RFC specifications and Python implementations.
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 4: CRYPTOGRAPHIC SIMULATION STEPS */}
      <section id="simulation" className="section section-soft">
        <div className="container">
          <div className="section-header">
            <div className="section-pill">SECTION 4</div>
            <h2 className="section-title">Cryptographic Simulation</h2>
            <p className="section-subtitle">Execute the 4 core steps of the S/MIME protocol in sequence</p>
          </div>

          {/* Step Progress Indicator */}
          <div className="steps-progress-bar">
            <div className={`step-bubble ${currentStep >= 1 ? 'completed' : ''} ${currentStep === 1 ? 'active' : ''}`}>
              <span className="step-num">1</span>
              <span className="step-text">Generate Keys</span>
            </div>
            <div className={`step-line ${currentStep >= 2 ? 'filled' : ''}`}></div>

            <div className={`step-bubble ${currentStep >= 2 ? 'completed' : ''} ${currentStep === 2 ? 'active' : ''}`}>
              <span className="step-num">2</span>
              <span className="step-text">Sign Message</span>
            </div>
            <div className={`step-line ${currentStep >= 3 ? 'filled' : ''}`}></div>

            <div className={`step-bubble ${currentStep >= 3 ? 'completed' : ''} ${currentStep === 3 ? 'active' : ''}`}>
              <span className="step-num">3</span>
              <span className="step-text">Encrypt Email</span>
            </div>
            <div className={`step-line ${currentStep >= 4 ? 'filled' : ''}`}></div>

            <div className={`step-bubble ${currentStep >= 4 ? 'completed' : ''} ${currentStep === 4 ? 'active' : ''}`}>
              <span className="step-num">4</span>
              <span className="step-text">Decrypt &amp; Verify</span>
            </div>
          </div>

          {/* Simulation 4-Cards Grid */}
          <div className="cards-grid-4">
            {/* Step 1 Card */}
            <div className={`sim-step-card ${currentStep >= 1 ? 'card-done' : ''}`}>
              <div className="sim-step-header">
                <span className="sim-step-badge">STEP 1</span>
                <span className="sim-status-label">{senderKeys ? '✓ READY' : 'PENDING'}</span>
              </div>
              <h4 className="sim-step-title">Generate Keys</h4>
              <p className="sim-step-desc">
                Generate 2048-bit RSA key pairs: Alice gets RSA-PSS (signing), Bob gets RSA-OAEP (encryption).
              </p>
              <button
                className="btn btn-pink"
                onClick={handleGenerateKeys}
              >
                {senderKeys ? 'Regenerate Keys' : '1. Generate Keys'}
              </button>
            </div>

            {/* Step 2 Card */}
            <div className={`sim-step-card ${currentStep >= 2 ? 'card-done' : ''}`}>
              <div className="sim-step-header">
                <span className="sim-step-badge">STEP 2</span>
                <span className="sim-status-label">{signatureRaw ? '✓ READY' : 'PENDING'}</span>
              </div>
              <h4 className="sim-step-title">Sign Message</h4>
              <p className="sim-step-desc">
                Compute SHA-256 digest of email content and sign using Alice's RSA Private Key.
              </p>
              <button
                className="btn btn-pink"
                onClick={handleSignMessage}
                disabled={!senderKeys}
              >
                2. Sign Message
              </button>
            </div>

            {/* Step 3 Card */}
            <div className={`sim-step-card ${currentStep >= 3 ? 'card-done' : ''}`}>
              <div className="sim-step-header">
                <span className="sim-step-badge">STEP 3</span>
                <span className="sim-status-label">{encryptedPayload ? '✓ READY' : 'PENDING'}</span>
              </div>
              <h4 className="sim-step-title">Encrypt Email</h4>
              <p className="sim-step-desc">
                Encrypt email using AES-256 session key, then wrap AES key with Bob's RSA Public Key.
              </p>
              <button
                className="btn btn-pink"
                onClick={handleEncryptEmail}
                disabled={!signatureRaw}
              >
                3. Encrypt Email
              </button>
            </div>

            {/* Step 4 Card */}
            <div className={`sim-step-card ${currentStep >= 4 ? 'card-done' : ''}`}>
              <div className="sim-step-header">
                <span className="sim-step-badge">STEP 4</span>
                <span className="sim-status-label">{isDecrypted ? '✓ COMPLETE' : 'PENDING'}</span>
              </div>
              <h4 className="sim-step-title">Decrypt &amp; Verify</h4>
              <p className="sim-step-desc">
                Unwrap AES key with Bob's private key, decrypt email, and verify Alice's digital signature.
              </p>
              <button
                className="btn btn-pink"
                onClick={handleDecryptAndVerify}
                disabled={!encryptedPayload}
              >
                4. Decrypt &amp; Verify
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 5: LIVE DEMONSTRATION & WORKSPACE */}
      <section id="demo" className="section">
        <div className="container">
          <div className="section-header">
            <div className="section-pill">SECTION 5</div>
            <h2 className="section-title">Live Demonstration</h2>
            <p className="section-subtitle">Interactive experiment inputs, controls, and inspectable cryptographic artifacts</p>
          </div>

          {/* Feedback Banner */}
          {feedback && (
            <div className={feedbackType === 'error' ? 'alert alert-error' : 'alert alert-info'}>
              {feedback}
            </div>
          )}

          <div className="demo-grid">
            {/* Input & Control Column */}
            <div className="demo-card">
              <div className="demo-card-title">EMAIL COMPOSER &amp; CONTROLS</div>

              <div className="form-row">
                <div className="form-group half-width">
                  <label className="form-label">Sender Email (Alice)</label>
                  <input
                    type="email"
                    className="form-input"
                    value={senderEmail}
                    onChange={(e) => setSenderEmail(e.target.value)}
                  />
                </div>
                <div className="form-group half-width">
                  <label className="form-label">Receiver Email (Bob)</label>
                  <input
                    type="email"
                    className="form-input"
                    value={receiverEmail}
                    onChange={(e) => setReceiverEmail(e.target.value)}
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Email Message (Plaintext)</label>
                <textarea
                  className="form-textarea"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Enter message to secure with S/MIME..."
                />
              </div>

              <div className="controls-grid">
                <button className="btn btn-pink" onClick={handleGenerateKeys}>
                  1. Generate Keys
                </button>
                <button className="btn btn-outline" onClick={handleSignMessage} disabled={!senderKeys}>
                  2. Sign Message
                </button>
                <button className="btn btn-pink" onClick={handleEncryptEmail} disabled={!signatureRaw}>
                  3. Encrypt Email
                </button>
                <button className="btn btn-outline" onClick={handleDecryptAndVerify} disabled={!encryptedPayload}>
                  4. Decrypt &amp; Verify
                </button>
              </div>

              <div className="secondary-controls">
                <button className="btn btn-ghost" onClick={handleReset}>
                  ↺ Reset All Fields
                </button>
              </div>

              {/* Explanatory "What happened?" panel */}
              <div className="explanation-box">
                <div className="explanation-title">💡 What happens in this step?</div>
                {currentStep === 0 && (
                  <p className="explanation-desc">
                    Ready to start. Click <strong>"1. Generate Keys"</strong> to create mathematically linked public/private key pairs for Alice and Bob using the browser's native Web Crypto API.
                  </p>
                )}
                {currentStep === 1 && (
                  <p className="explanation-desc">
                    <strong>Keys Generated:</strong> Alice holds an RSA-PSS key pair for producing signatures. Bob holds an RSA-OAEP key pair for decrypting symmetric session keys.
                  </p>
                )}
                {currentStep === 2 && (
                  <p className="explanation-desc">
                    <strong>Signature Created:</strong> The message was hashed via SHA-256. Alice's private key signed this hash, guaranteeing authentic origin and unforgeability.
                  </p>
                )}
                {currentStep === 3 && (
                  <p className="explanation-desc">
                    <strong>Email Encrypted:</strong> A one-time AES-256 session key encrypted the email body. That AES key was then encrypted with Bob's public key (RSA-OAEP).
                  </p>
                )}
                {currentStep >= 4 && (
                  <p className="explanation-desc">
                    <strong>Decrypted &amp; Verified:</strong> Bob unpacked the AES key with his private key, decrypted the message, and verified the signature using Alice's public key.
                  </p>
                )}
              </div>
            </div>

            {/* Cryptographic Inspection Column */}
            <div className="demo-card">
              <div className="demo-card-title">INSPECTION &amp; CRYPTOGRAPHIC OUTPUT</div>

              {/* Artifact: SHA-256 Digest */}
              <div className="artifact-item">
                <div className="artifact-label">1. SHA-256 Message Digest</div>
                <div className="artifact-value">
                  {messageHash ? (
                    <span className="mono-text">{messageHash}</span>
                  ) : (
                    <span className="text-muted">Awaiting step 2 (Sign Message)...</span>
                  )}
                </div>
              </div>

              {/* Artifact: Digital Signature */}
              <div className="artifact-item">
                <div className="artifact-label">2. Digital Signature (RSA-PSS 2048-bit Preview)</div>
                <div className="artifact-value">
                  {signatureHex ? (
                    <span className="mono-text text-pink">
                      {signatureHex.substring(0, 32)}...{signatureHex.substring(signatureHex.length - 24)}
                    </span>
                  ) : (
                    <span className="text-muted">Awaiting step 2 (Sign Message)...</span>
                  )}
                </div>
              </div>

              {/* Artifact: AES Ciphertext */}
              <div className="artifact-item">
                <div className="artifact-label">3. Encrypted Email Body (AES-256 Ciphertext)</div>
                <div className="artifact-value">
                  {encryptedPayload ? (
                    <span className="mono-text">
                      {bufferToHex(encryptedPayload).substring(0, 48)}...
                    </span>
                  ) : (
                    <span className="text-muted">Awaiting step 3 (Encrypt Email)...</span>
                  )}
                </div>
              </div>

              {/* Artifact: Encrypted AES Session Key */}
              <div className="artifact-item">
                <div className="artifact-label">4. Wrapped AES Session Key (RSA-OAEP Encrypted)</div>
                <div className="artifact-value">
                  {encryptedAesKey ? (
                    <span className="mono-text text-maroon">
                      {bufferToHex(encryptedAesKey).substring(0, 36)}...
                    </span>
                  ) : (
                    <span className="text-muted">Awaiting step 3 (Encrypt Email)...</span>
                  )}
                </div>
              </div>

              {/* Artifact: Decrypted Plaintext Output */}
              {isDecrypted && (
                <div className="artifact-item outcome-box">
                  <div className="artifact-label">5. Recovered Decrypted Content</div>
                  <div className="artifact-value large-output">
                    "{decryptedMessage}"
                  </div>
                  <div className={`verification-badge ${isSignatureValid ? 'badge-success' : 'badge-failure'}`}>
                    {isSignatureValid ? '✓ DIGITAL SIGNATURE VALID (AUTHENTIC)' : '✗ DIGITAL SIGNATURE INVALID (TAMPERED)'}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 6: TAMPER / SECURITY TEST */}
      <section id="security-test" className="section section-soft">
        <div className="container">
          <div className="section-header">
            <div className="section-pill">SECTION 6</div>
            <h2 className="section-title">Tamper / Security Test</h2>
            <p className="section-subtitle">
              Simulate an Man-in-the-Middle (MitM) attacker modifying the email while in transit
            </p>
          </div>

          <div className="tamper-card">
            <div className="tamper-header">
              <span className="tamper-icon">⚠️</span>
              <div>
                <h3 className="tamper-title">Active Adversary Simulation</h3>
                <p className="tamper-subtitle">
                  Demonstrate how S/MIME detects unauthenticated message tampering and protects message integrity.
                </p>
              </div>
            </div>

            <div className="tamper-actions">
              <button
                className="btn btn-tamper"
                onClick={handleTamperMessage}
                disabled={!encryptedPayload}
              >
                ⚠️ Tamper Message in Transit
              </button>
              <button
                className="btn btn-outline"
                onClick={handleRestoreMessage}
                disabled={!isTampered}
              >
                ↺ Restore Original Message
              </button>
            </div>

            {/* Tampering Status Banner */}
            {isTampered && (
              <div className="tamper-active-banner">
                <div className="tamper-banner-alert">
                  <strong>Adversary Action:</strong> Intercepted email and modified content to:
                  <div className="tamper-hacked-text">"Hello Bob, this is a hacked email."</div>
                </div>

                {isDecrypted && isSignatureValid === false && (
                  <div className="tamper-fail-details">
                    <div className="fail-title">✗ CRYPTOGRAPHIC VERIFICATION RESULT:</div>
                    <ul className="fail-list">
                      <li>✗ DIGITAL SIGNATURE INVALID</li>
                      <li>✗ MESSAGE INTEGRITY FAILED</li>
                      <li>⚠ MESSAGE MODIFICATION DETECTED BY BOB'S EMAIL CLIENT</li>
                    </ul>
                    <p className="fail-explanation">
                      <strong>Why did it fail?</strong> The digital signature was computed over the SHA-256 hash of the <em>original</em> message. When the altered message is verified against Alice's public key, the cryptographic hash comparison fails. Bob is warned that the sender identity or message content has been compromised!
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* SECTION 7: RESULTS & OBSERVATION */}
      <section id="results" className="section">
        <div className="container">
          <div className="section-header">
            <div className="section-pill">SECTION 7</div>
            <h2 className="section-title">Results &amp; Observation</h2>
            <p className="section-subtitle">Side-by-side comparative analysis of normal transmission vs tampered transmission</p>
          </div>

          <div className="results-grid">
            {/* Normal Card */}
            <div className="result-card normal-card">
              <div className="result-card-header">
                <span className="result-status-dot green-dot"></span>
                <span className="result-card-badge">CASE 1</span>
              </div>
              <h3 className="result-scenario-title">Normal Transmission</h3>
              <div className="scenario-item">
                <span className="scenario-label">Original Content:</span>
                <span className="scenario-val">"Hello Bob, this is a secure email."</span>
              </div>
              <div className="scenario-item">
                <span className="scenario-label">Signature Verification:</span>
                <span className="scenario-val text-green font-bold">✓ PASSED</span>
              </div>
              <div className="scenario-item">
                <span className="scenario-label">Integrity Status:</span>
                <span className="scenario-val text-green">Intact &amp; Unaltered</span>
              </div>
              <div className="scenario-item">
                <span className="scenario-label">Sender Authenticity:</span>
                <span className="scenario-val text-green">Confirmed (Alice)</span>
              </div>
            </div>

            {/* Tampered Card */}
            <div className="result-card tampered-card">
              <div className="result-card-header">
                <span className="result-status-dot red-dot"></span>
                <span className="result-card-badge">CASE 2</span>
              </div>
              <h3 className="result-scenario-title">Tampered Transmission</h3>
              <div className="scenario-item">
                <span className="scenario-label">Altered Content:</span>
                <span className="scenario-val">"Hello Bob, this is a hacked email."</span>
              </div>
              <div className="scenario-item">
                <span className="scenario-label">Signature Verification:</span>
                <span className="scenario-val text-red font-bold">✗ FAILED</span>
              </div>
              <div className="scenario-item">
                <span className="scenario-label">Integrity Status:</span>
                <span className="scenario-val text-red">Violated (Tampered)</span>
              </div>
              <div className="scenario-item">
                <span className="scenario-label">Security Response:</span>
                <span className="scenario-val text-red">Message Rejected</span>
              </div>
            </div>
          </div>

          <div className="observation-summary-box">
            <strong>Observation Note:</strong> Even a single bit alteration in the ciphertext or decoded payload creates a completely mismatched SHA-256 digest, making undetected tampering mathematically impossible under RSA-PSS digital signatures.
          </div>
        </div>
      </section>

      {/* SECTION 8: CONCLUSION */}
      <section id="conclusion" className="section section-soft">
        <div className="container">
          <div className="section-header">
            <div className="section-pill">SECTION 8</div>
            <h2 className="section-title">Conclusion</h2>
            <p className="section-subtitle">Summary of security guarantees achieved by the S/MIME architecture</p>
          </div>

          <div className="conclusion-card">
            <h3 className="conclusion-heading">Key Takeaways from the Virtual Lab</h3>
            <div className="conclusion-points">
              <div className="point-item">
                <span className="point-check">✓</span>
                <div>
                  <strong>Confidentiality via AES-256:</strong> Bulk email content is encrypted at maximum throughput using symmetric keys, preventing unauthorized third parties from intercepting cleartext.
                </div>
              </div>

              <div className="point-item">
                <span className="point-check">✓</span>
                <div>
                  <strong>Key Exchange via RSA-OAEP:</strong> Asymmetric public-key encryption securely transports the one-time AES session key without prior shared secret requirements.
                </div>
              </div>

              <div className="point-item">
                <span className="point-check">✓</span>
                <div>
                  <strong>Authenticity &amp; Non-Repudiation via RSA-PSS:</strong> Alice's private key signature proves undeniable origin and identity verification for Bob.
                </div>
              </div>

              <div className="point-item">
                <span className="point-check">✓</span>
                <div>
                  <strong>Integrity Verification via SHA-256:</strong> Any message modification in transit invalidates the digital signature immediately, warning the recipient before accepting compromised information.
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="footer">
        <div className="container footer-content">
          <div className="footer-title">S/MIME SECURE EMAIL – VIRTUAL LABORATORY</div>
          <p className="footer-sub">Department of Computer Science &amp; Engineering • College Cryptography Assignment</p>
          <div className="footer-team">
            <span>Project Team: <strong>Mohammad Zeeshan (4MW23CS072)</strong> &amp; <strong>Mohd Arman (4MW23CS075)</strong></span>
          </div>
          <div className="footer-note">
            Built with React, Vite &amp; Web Crypto API • Ready for presentation &amp; Netlify deployment
          </div>
        </div>
      </footer>
    </div>
  );
}
