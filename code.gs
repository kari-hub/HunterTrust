// Trigger when the add-on is opened
function onOpen(e) {
  if (e.gmail && e.gmail.messageId) {
    return detectLinksAction(e);
  }
  return createNoEmailCard();
}

function onHome(e) {
  return createNoEmailCard().build();
}

// Card to show when no email is selected
function createNoEmailCard() {
  var card = CardService.newCardBuilder();
  var cardHeader = CardService.newCardHeader()
    .setTitle('HunterTrust')
    .setSubtitle('No email available to scan.');

  var cardSection = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        'HunterTrust did not find an email to scan. Please open an email to start scanning for phishing or malicious links.'
      )
    );

  return card.setHeader(cardHeader).addSection(cardSection).build();
}
// Detect BEC indicators in email body
function detectBECIndicators(body) {
  var becPatterns = [
    'your account has been hacked',
    'your account will be suspended',
    'send payment immediately',
    'click here to verify',
    'Send me the information urgently',
    'we have detected suspicious activity',
    'confirm your login details',
    'reset your password now',
    'verify your account'
  ];

  var detectedIndicators = [];

  for (var i = 0; i < becPatterns.length; i++) {
    var pattern = becPatterns[i].toLowerCase();
    if (body.toLowerCase().includes(pattern)) {
      detectedIndicators.push(pattern);
    }
  }

  return detectedIndicators;
}


// Main function to analyze the sender's email address and domain
function detectLinksAction(e) {
  Logger.log(JSON.stringify(e));

  if (!e || !e.gmail || !e.gmail.messageId) {
    Logger.log('No messageId found.');
    return createNoEmailCard().build();
  }

  var messageId = e.gmail.messageId;
  var message = GmailApp.getMessageById(messageId);
  var body = message.getPlainBody();
  var subject = message.getSubject();
  var sender = message.getFrom();
  var links = extractUrls(body);

  var cache = CacheService.getUserCache();
  var result = '<b>Links found in the email:</b><br><br>';

  // Validate sender and domain
  var isTrustedSender = validateSender(sender);
  var senderStatus = isTrustedSender
    ? '✅ Trusted Sender: ' + sender
    : '🚨 Suspicious Sender: ' + sender;

  result += senderStatus + '<br><br>';

  // Check for potential phishing indicators in the subject and sender
  var behavioralAnalysis = analyzeBehavior(subject, sender);
  if (behavioralAnalysis) {
    result += behavioralAnalysis + '<br><br>';
  }

  // Check for BEC patterns in the email body
  var becIndicators = detectBECIndicators(body);
  if (becIndicators.length > 0) {
    result += '⚠️ **BEC Indicators Detected in Email Body:**<br>';
    result += becIndicators.map(indicator => '- ' + indicator).join('<br>') + '<br><br>';
  }

  var analyzedLinks = {}; // Track processed URLs

  if (links.length > 0) {
    for (var i = 0; i < links.length; i++) {
      var link = links[i];
      var linkHash = generateHash(link); // Generate a unique hash for each link

      if (analyzedLinks[linkHash]) {
        continue; // Skip already processed URLs
      }

      var cachedResult = cache.get(linkHash);
      var isMalicious;

      if (cachedResult !== null) {
        isMalicious = cachedResult === 'true';
      } else {
        isMalicious = checkMalicious(link);
        if (isMalicious !== null) {
          cache.put(linkHash, isMalicious ? 'true' : 'false', 21600); // Cache for 6 hours
        }
      }

      var statusText =
        isMalicious === true
          ? 'Malicious'
          : isMalicious === false
          ? 'Safe'
          : 'Unknown status';

      result += generateLinkResult(link, statusText);
      analyzedLinks[linkHash] = true; // Mark the link as processed
    }
  } else {
    result += 'No links found in the email.';
  }

  // User education section
  result +=
    '<br><br><b>Tips to Recognize Phishing:</b><br>' +
    "1. Check the sender's email address.<br>" +
    '2. Be cautious of urgent requests.<br>' +
    '3. Hover over links to see the actual URL before clicking.';

  // Display results in a card
  var card = CardService.newCardBuilder();
  var cardHeader = CardService.newCardHeader().setTitle('HunterTrust - Email Scan Results');
  var cardSection = CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText(result)
  );

  return card.setHeader(cardHeader).addSection(cardSection).build();
}

// Validate sender email against trusted domains or email addresses
function validateSender(senderEmail) {
  var trustedDomains = ['students@dkut.ac.ke']; // Example trusted domains
  var trustedEmails = ['nderitu.esther21@students.dkut.ac.ke']; // Example trusted emails

  // Clean the sender email by removing any display name and angle brackets
  var cleanedSender = senderEmail.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);

  if (cleanedSender) {
    senderEmail = cleanedSender[0]; // Properly cleaned email
  } else {
    Logger.log('Unable to extract a valid email address from: ' + senderEmail);
    return false; // Return false if unable to clean the email address
  }

  var senderDomain = senderEmail.split('@')[1].toLowerCase();  // Extract domain

  Logger.log('Sender Email: ' + senderEmail);
  Logger.log('Sender Domain: ' + senderDomain);

  // Check if sender email or domain is in the trusted list
  if (trustedEmails.includes(senderEmail)) {
    Logger.log('Trusted email found: ' + senderEmail);
    return true; // Trusted sender
  }

  if (trustedDomains.includes(senderDomain)) {
    Logger.log('Trusted domain found: ' + senderDomain);
    return true; // Trusted sender
  }

  // Add check for domain spoofing using Levenshtein Distance
  if (isSpoofedDomain(senderDomain, trustedDomains)) {
    Logger.log('Spoofed domain detected: ' + senderDomain);
    return false; // Spoofed domain detected
  }

  return false; // Not a trusted sender
}

// Check if domain is spoofed by comparing with trusted domains
function isSpoofedDomain(senderDomain, trustedDomains) {
  for (var trustedDomain of trustedDomains) {
    if (getLevenshteinDistance(senderDomain, trustedDomain) <= 2) { // Allow small variations
      return true; // Domain is spoofed
    }
  }
  return false;
}

// Levenshtein Distance algorithm to detect domain spoofing
function getLevenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  if (a.length > b.length) { [a, b] = [b, a]; } // Ensure `a` is the shorter string

  var alen = a.length, blen = b.length;
  var row = Array(alen + 1).fill(0).map((_, i) => i); // Initialize the first row

  let res;
  for (let i = 1; i <= blen; i++) {
    res = i;
    for (let j = 1; j <= alen; j++) {
      let tmp = row[j - 1];
      row[j - 1] = res;
      res = a[j - 1] === b[i - 1] ? tmp : Math.min(tmp + 1, Math.min(res + 1, row[j] + 1));
    }
  }
  return res;
}

// Analyze email subject and sender for behavioral phishing indicators
function analyzeBehavior(subject, sender) {
  var suspiciousKeywords = [
    'urgent',
    'action required',
    'immediate response',
    'verify your account',
    'update your details',
    'account suspended',
    'immediate action',
    'send money',
    'transfer funds',
    'wire transfer',
    'payment',
    'bank details',
    'account details',
    'financial information',
    'immediately',
    'as soon as possible',
    'now',
    'payment request',
    'large amount',
    'sensitive information'
  ];
  var senderDomain = sender.split('@')[1].toLowerCase();

  for (var keyword of suspiciousKeywords) {
    if (subject.toLowerCase().includes(keyword)) {
      return '⚠️ **Warning:** The subject contains suspicious language: ' + keyword;
    }
  }
}

// Extract URLs from email body
function extractUrls(text) {
  var regex = /(https?:\/\/[^\s<>)"']+)/g;  // Exclude more trailing characters
  var urls = [];
  var match;

  while ((match = regex.exec(text)) !== null) {
    var cleanUrl = match[0].replace(/[)"'>]+$/, ''); // Remove trailing quotes, parentheses, or greater-than signs
    urls.push(cleanUrl);
  }

  return urls;
}

// Check if the link is malicious using VirusTotal API
function checkMalicious(link) {
  var apiKey = 'e57070a6516b22962acc0eb68ff8c2586b343d44b4014d2c8624dac91f7d07a6'; 
  var scanUrl = 'https://www.virustotal.com/vtapi/v2/url/report';
  var baseUrl = link.split(/[?#]/)[0]; // Analyze base URL

  var payload = {
    apikey: apiKey,
    url: baseUrl, // VirusTotal expects the full URL for analysis
  };

  var options = {
    method: 'post',
    contentType: 'application/x-www-form-urlencoded',
    payload: payload,
  };

  try {
    var response = UrlFetchApp.fetch(scanUrl, options);
    var json = JSON.parse(response.getContentText());
    var positives = json.positives || 0;
    var total = json.total || 1;

    return positives > 0;
  } catch (error) {
    Logger.log('Error checking link with VirusTotal: ' + error.message);
    return null;
  }
}

// Generate a unique hash for each link
function generateHash(link) {
  return Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, link));
}

// Format the link result with appropriate color-coding
function generateLinkResult(link, status) {
  var color = status === 'Malicious' ? 'red' : status === 'Safe' ? 'green' : 'yellow';
  return (
    '<span style="color: ' +
    color +
    '">Link: <a href="' +
    link +
    '" target="_blank">' +
    link +
    '</a> - Status: ' +
    status +
    '</span><br>'
  );
}
