# HunterTrust Email Add-on

HunterTrust is a browser-based email monitoring extension designed to combat the rising threat of phishing attacks, particularly Business Email Compromise (BEC) scenarios. BEC attacks exploit vulnerabilities in email communication, targeting executives and employees to manipulate them into performing actions like transferring money or sharing sensitive information. These attacks can lead to significant financial losses and reputational damage for organizations.


## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Infrastructure](#infrastructure)
5. [Results of the Add-on](#results-of-the-add-on)
6. [Code Explanation](#code-explanation)
7. [Contributing](#contributing)
8. [License](#license)

## Features

- **Email Scanning**: Automatically scans emails for phishing indicators and malicious links.
- **Real-time Analysis**: Uses VirusTotal API for link reputation checks, ensuring users can verify the safety of URLs.
- **User Education**: Provides tips to recognize phishing attempts, helping users become more security-aware.
- **Behavioral Analysis**: Checks the sender's domain and email patterns for suspicious activity, enhancing detection accuracy.
- **Trust Validation**: Validates the sender against a list of trusted domains and emails to prevent spoofing attacks.

## Installation

To set up the HunterTrust add-on in your Google Workspace, follow these steps:

1. Open Google Apps Script editor.
2. Create a new project.
3. Copy and paste the provided code into the editor.
4. Save the project and deploy it as a web app or add-on.
5. Grant necessary permissions for Gmail access.

## Usage

1. Open an email in your Gmail inbox.
2. The HunterTrust add-on will automatically trigger and analyze the email.
3. View the results, which will display any detected phishing indicators, the status of links, and tips on how to identify phishing attempts.

## Infrastructure

The HunterTrust add-on is built on the following components:

- **Gmail API**: Used to access and analyze email messages.
- **Google Apps Script**: The primary framework for scripting and deploying the add-on.
- **VirusTotal API**: Integrated for link analysis to check if any URLs in the email are known to be malicious.
- **Caching**: Utilizes Google’s CacheService to store link analysis results and sender behaviors, improving performance and reducing redundant API calls.

## Results of the Add-on

When using the HunterTrust add-on, users can expect the following results:

- **Phishing Indicator Detection**: The add-on highlights potential phishing indicators in the email, such as urgent language or unusual sender behavior.
- **Link Safety Assessment**: All links in the email are checked against the VirusTotal database, with results color-coded:
  - **Green**: Safe link.
  - **Yellow**: Suspicious link; further investigation recommended.
  - **Red**: Malicious link; warnings provided.
- **Sender Validation**: The sender’s email address is validated against trusted domains. Users are notified if the sender's domain appears to be spoofed.
- **Educational Tips**: Users receive tailored tips on identifying phishing attempts, enhancing their awareness and security posture.

## Code Explanation

### Main Functions

- **onOpen**: Triggered when the add-on is opened. It checks if an email is selected and calls `detectLinksAction` to analyze it.
- **createNoEmailCard**: Displays a message when no email is selected.
- **detectBECIndicators**: Checks the email body for known BEC patterns.
- **detectLinksAction**: Main function to analyze email content, validate the sender, and check for malicious links.
- **validateSender**: Validates the sender's email against trusted domains and emails.
- **isSpoofedDomain**: Checks if the sender's domain is spoofed using Levenshtein Distance.
- **extractUrls**: Extracts URLs from the email body.
- **checkMalicious**: Uses VirusTotal API to determine if a link is malicious.
- **generateLinkResult**: Formats the link result with color-coding based on its status.

### Additional Features

- **User Behavior Tracking**: Tracks the frequency of emails from a sender to identify potential spam or phishing patterns.
- **Education Section**: Provides tips on recognizing phishing attempts to educate users.

## Contributing

We welcome contributions! If you would like to improve HunterTrust, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes and create a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
# HunterTrust Email Add-on

HunterTrust is a browser-based email monitoring extension designed to combat the rising threat of phishing attacks, particularly Business Email Compromise (BEC) scenarios. BEC attacks exploit vulnerabilities in email communication, targeting executives and employees to manipulate them into performing actions like transferring money or sharing sensitive information. These attacks can lead to significant financial losses and reputational damage for organizations.

### **Problem Being Solved**

Despite advancements in email security measures, phishing attacks remain prevalent, with attackers constantly evolving their tactics. Traditional email filters often fail to catch sophisticated phishing attempts, especially those that are context-specific and mimic legitimate communications. HunterTrust addresses this critical gap by providing a comprehensive analysis of incoming emails, focusing on behavioral patterns, link safety, and sender validation. By equipping users with real-time insights and education, HunterTrust aims to empower individuals and organizations to recognize and respond to potential threats effectively.

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Infrastructure](#infrastructure)
5. [Results of the Add-on](#results-of-the-add-on)
6. [Code Explanation](#code-explanation)
7. [Contributing](#contributing)
8. [License](#license)

## Features

- **Email Scanning**: Automatically scans emails for phishing indicators and malicious links.
- **Real-time Analysis**: Uses VirusTotal API for link reputation checks, ensuring users can verify the safety of URLs.
- **User Education**: Provides tips to recognize phishing attempts, helping users become more security-aware.
- **Behavioral Analysis**: Checks the sender's domain and email patterns for suspicious activity, enhancing detection accuracy.
- **Trust Validation**: Validates the sender against a list of trusted domains and emails to prevent spoofing attacks.

## Installation

To set up the HunterTrust add-on in your Google Workspace, follow these steps:

1. Open Google Apps Script editor.
2. Create a new project.
3. Copy and paste the provided code into the editor.
4. Save the project and deploy it as a web app or add-on.
5. Grant necessary permissions for Gmail access.

## Usage

1. Open an email in your Gmail inbox.
2. The HunterTrust add-on will automatically trigger and analyze the email.
3. View the results, which will display any detected phishing indicators, the status of links, and tips on how to identify phishing attempts.

## Infrastructure

The HunterTrust add-on is built on the following components:

- **Gmail API**: Used to access and analyze email messages.
- **Google Apps Script**: The primary framework for scripting and deploying the add-on.
- **VirusTotal API**: Integrated for link analysis to check if any URLs in the email are known to be malicious.
- **Caching**: Utilizes Google’s CacheService to store link analysis results and sender behaviors, improving performance and reducing redundant API calls.

## Results of the Add-on

When using the HunterTrust add-on, users can expect the following results:

- **Phishing Indicator Detection**: The add-on highlights potential phishing indicators in the email, such as urgent language or unusual sender behavior.
- **Link Safety Assessment**: All links in the email are checked against the VirusTotal database, with results color-coded:
  - **Green**: Safe link.
  - **Yellow**: Suspicious link; further investigation recommended.
  - **Red**: Malicious link; warnings provided.
- **Sender Validation**: The sender’s email address is validated against trusted domains. Users are notified if the sender's domain appears to be spoofed.
- **Educational Tips**: Users receive tailored tips on identifying phishing attempts, enhancing their awareness and security posture.

## Code Explanation

### Main Functions

- **onOpen**: Triggered when the add-on is opened. It checks if an email is selected and calls `detectLinksAction` to analyze it.
- **createNoEmailCard**: Displays a message when no email is selected.
- **detectBECIndicators**: Checks the email body for known BEC patterns.
- **detectLinksAction**: Main function to analyze email content, validate the sender, and check for malicious links.
- **validateSender**: Validates the sender's email against trusted domains and emails.
- **isSpoofedDomain**: Checks if the sender's domain is spoofed using Levenshtein Distance.
- **extractUrls**: Extracts URLs from the email body.
- **checkMalicious**: Uses VirusTotal API to determine if a link is malicious.
- **generateLinkResult**: Formats the link result with color-coding based on its status.

### Additional Features

- **User Behavior Tracking**: Tracks the frequency of emails from a sender to identify potential spam or phishing patterns.
- **Education Section**: Provides tips on recognizing phishing attempts to educate users.

## Contributing

We welcome contributions! If you would like to improve HunterTrust, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes and create a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
