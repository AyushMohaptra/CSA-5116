def email_phishing_detector(email_text):
    # Simulated Feature Extraction (Keywords often found in phishing)
    phishing_keywords = ['urgent', 'password', 'verify', 'bank', 'account suspended', 'click here']
    
    email_lower = email_text.lower()
    score = 0
    
    print(f"Analyzing Email: '{email_text}'")
    
    for word in phishing_keywords:
        if word in email_lower:
            score += 1
            print(f" -> Flagged suspicious keyword: '{word}'")
            
    # Classification Threshold
    if score >= 2:
        return "PHISHING DETECTED"
    else:
        return "SAFE EMAIL"

def run_tests():
    # Test Cases
    email_1 = "URGENT: Your bank account is suspended. Click here to verify your password."
    email_2 = "Hi team, let's schedule a meeting for tomorrow to discuss the project."
    
    print("--- Test 1 ---")
    result_1 = email_phishing_detector(email_1)
    print(f"Classification: {result_1}\n")
    
    print("--- Test 2 ---")
    result_2 = email_phishing_detector(email_2)
    print(f"Classification: {result_2}")

if __name__ == "__main__":
    run_tests()
