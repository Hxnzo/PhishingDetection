# # phishing_detector.py code:

# import requests 
# import urllib3
# import pandas as pd
# import numpy as np
# import re
# from bs4 import BeautifulSoup
# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import StandardScaler
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.svm import SVC
# from sklearn.metrics import accuracy_score, confusion_matrix, roc_curve, precision_recall_curve
# import tensorflow as tf
# from sklearn.decomposition import PCA
# import matplotlib.pyplot as plt
# import pickle
# import os
# import warnings
# import tldextract
# from urllib.parse import urlparse

# # Disable SSL warnings to allow scraping of potential phishing sites
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# warnings.filterwarnings('ignore')

# class PhishingDetector:
#     def __init__(self):
#         self.model_rf = None
#         self.model_svm = None
#         self.model_nn = None
#         self.scaler = StandardScaler()
#         self.features = []
        
#     def scrape_website(self, url):
#         """
#         Scrape the website content from a given URL with improved reliability
#         """
#         try:
#             # More realistic user agent
#             headers = {
#                 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
#                 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
#                 'Accept-Language': 'en-US,en;q=0.5',
#                 'Connection': 'keep-alive',
#                 'Upgrade-Insecure-Requests': '1',
#                 'DNT': '1',
#             }
            
#             # Use a timeout to prevent hanging on slow sites
#             response = requests.get(url, headers=headers, verify=False, timeout=10)
            
#             # Check if response is successful
#             if response.status_code == 200:
#                 html_content = response.text
#                 return html_content
#             else:
#                 print(f"Failed to retrieve {url}: Status code {response.status_code}")
#                 return None
                
#         except requests.exceptions.Timeout:
#             print(f"Timeout occurred while scraping {url}")
#             return None
#         except requests.exceptions.TooManyRedirects:
#             print(f"Too many redirects for {url}")
#             return None
#         except requests.exceptions.RequestException as e:
#             print(f"Error scraping {url}: {str(e)}")
#             return None
    
#     def extract_features(self, url, html_content=None):
#         """
#         Extract features from URL and HTML content with improved detection capabilities
#         """
#         # Normalize trailing slash so "https://google.com/" == "https://google.com"
#         url = url.rstrip('/')

#         features = {}
        
#         # Parse URL components
#         parsed_url = urlparse(url)
#         domain_info = tldextract.extract(url)
        
#         # URL features
#         features['url_length'] = len(url)
#         features['domain_length'] = len(domain_info.domain)
#         features['num_dots'] = url.count('.')
#         features['num_hyphens'] = url.count('-')
#         features['num_underscores'] = url.count('_')
#         features['num_slashes'] = url.count('/')
#         features['num_question_marks'] = url.count('?')
#         features['num_equal_signs'] = url.count('=')
#         features['num_at_symbols'] = url.count('@')
#         features['num_ampersands'] = url.count('&')
#         features['has_https'] = 1 if url.startswith('https://') else 0
#         features['num_digits'] = sum(c.isdigit() for c in url)
#         features['num_parameters'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
#         features['uses_ip_address'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_info.domain) else 0
#         features['suspicious_tld'] = 1 if domain_info.suffix in ['xyz', 'top', 'ml', 'ga', 'cf', 'gq', 'tk'] else 0
#         features['domain_age_days'] = 0  # Placeholder - could be implemented with WHOIS API
        
#         # If HTML content was not successfully retrieved, fill HTML features with zeros
#         if html_content is None:
#             features['num_iframes'] = 0
#             features['num_scripts'] = 0
#             features['num_links'] = 0
#             features['num_suspicious_tags'] = 0
#             features['num_forms'] = 0
#             features['num_images'] = 0
#             features['has_password_field'] = 0
#             features['external_redirects'] = 0
#             features['invisible_elements'] = 0
#             features['popup_count'] = 0
#             features['tiny_text'] = 0
#             features['favicon_mismatch'] = 0
#             features['has_login_form'] = 0
#             features['has_submit_button'] = 0
#             features['obfuscated_js'] = 0
#             return features
            
#         # Parse HTML content
#         soup = BeautifulSoup(html_content, 'html.parser')
        
#         # HTML features
#         features['num_iframes'] = len(soup.find_all('iframe'))
#         features['num_scripts'] = len(soup.find_all('script'))
#         features['num_links'] = len(soup.find_all('a'))
        
#         # Count suspicious HTML tags (often used in phishing)
#         suspicious_tags = ['form', 'input', 'button', 'select', 'textarea', 'meta', 'link', 'embed', 'object']
#         features['num_suspicious_tags'] = sum(len(soup.find_all(tag)) for tag in suspicious_tags)
        
#         # Forms and password fields
#         forms = soup.find_all('form')
#         features['num_forms'] = len(forms)
#         features['has_password_field'] = 1 if soup.find('input', {'type': 'password'}) else 0
#         features['has_login_form'] = 1 if soup.find('form') and soup.find('input', {'type': 'password'}) else 0
#         features['has_submit_button'] = 1 if soup.find('button', {'type': 'submit'}) or soup.find('input', {'type': 'submit'}) else 0
        
#         # Images
#         images = soup.find_all('img')
#         features['num_images'] = len(images)
        
#         # Check for tiny text (potential hidden content)
#         tiny_text_elements = soup.find_all(style=re.compile(r'font-size:\s*[0-1]px|visibility:\s*hidden|display:\s*none'))
#         features['tiny_text'] = len(tiny_text_elements)
        
#         # Check for invisible elements
#         invisible_elements = soup.find_all(style=re.compile(r'opacity:\s*0|visibility:\s*hidden|display:\s*none'))
#         features['invisible_elements'] = len(invisible_elements)
        
#         # Check for popups
#         popup_elements = soup.find_all(lambda tag: tag.name == 'script' and 
#                                       ('window.open' in tag.text or 'popup' in tag.text or 'alert(' in tag.text))
#         features['popup_count'] = len(popup_elements)
        
#         # Check for favicon mismatch (common in phishing)
#         favicon_links = soup.find_all('link', rel='icon') + soup.find_all('link', rel='shortcut icon')
#         features['favicon_mismatch'] = 0
#         if favicon_links:
#             for link in favicon_links:
#                 if 'href' in link.attrs:
#                     favicon_url = link['href']
#                     if favicon_url.startswith('http') and domain_info.domain not in favicon_url:
#                         features['favicon_mismatch'] = 1
#                         break
        
#         # External redirects in links
#         external_redirects = 0
#         domain = domain_info.domain
        
#         for link in soup.find_all('a', href=True):
#             href = link['href']
#             if href.startswith('http') and domain not in href:
#                 external_redirects += 1
        
#         features['external_redirects'] = external_redirects
        
#         # Check for obfuscated JavaScript
#         obfuscated_js = 0
#         for script in soup.find_all('script'):
#             if script.string and any(x in script.string for x in ['eval(', 'unescape(', 'fromCharCode', 'String.fromCharCode']):
#                 obfuscated_js += 1
#         features['obfuscated_js'] = obfuscated_js
        
#         return features
    
#     def create_dataset(self, legitimate_urls_file, phishing_urls_file, output_file='phishing_dataset.csv'):
#         """
#         Create a dataset from lists of legitimate and phishing URLs
#         """
#         # Load URLs
#         legitimate_urls = pd.read_csv(legitimate_urls_file, header=None)[0].tolist()
#         phishing_urls = pd.read_csv(phishing_urls_file, header=None)[0].tolist()
        
#         data = []
        
#         # Process legitimate URLs
#         print(f"Processing {len(legitimate_urls)} legitimate URLs...")
#         for url in legitimate_urls:
#             try:
#                 url = url.rstrip('/')
#                 html_content = self.scrape_website(url)
#                 features = self.extract_features(url, html_content)
#                 features['is_phishing'] = 0  # Not phishing
#                 data.append(features)
#             except Exception as e:
#                 print(f"Error processing {url}: {str(e)}")
        
#         # Process phishing URLs
#         print(f"Processing {len(phishing_urls)} phishing URLs...")
#         for url in phishing_urls:
#             try:
#                 url = url.rstrip('/')
#                 html_content = self.scrape_website(url)
#                 features = self.extract_features(url, html_content)
#                 features['is_phishing'] = 1  # Phishing
#                 data.append(features)
#             except Exception as e:
#                 print(f"Error processing {url}: {str(e)}")
        
#         # Create DataFrame and save to CSV
#         df = pd.DataFrame(data)
#         df.to_csv(output_file, index=False)
#         print(f"Dataset created and saved to {output_file}")
#         return df
    
#     def load_or_create_dataset(self, legitimate_urls_file, phishing_urls_file, output_file='phishing_dataset.csv'):
#         """
#         Load dataset if it exists, otherwise create it
#         """
#         if os.path.exists(output_file):
#             print(f"Loading existing dataset from {output_file}")
#             return pd.read_csv(output_file)
#         else:
#             return self.create_dataset(legitimate_urls_file, phishing_urls_file, output_file)
    
#     def train_models(self, legitimate_urls, phishing_urls, test_size=0.2, random_state=42, rf_estimators=200, svm_kernel='rbf', nn_epochs=30):
#         """
#         Train the machine learning models with the given URLs and parameters.
#         """
#         # Create dataset from URLs
#         print("Creating dataset from URLs...")
#         data = []
        
#         # Process legitimate URLs
#         print(f"Processing {len(legitimate_urls)} legitimate URLs...")
#         for url in legitimate_urls:
#             try:
#                 url = url.rstrip('/')
#                 html_content = self.scrape_website(url)
#                 features = self.extract_features(url, html_content)
#                 features['is_phishing'] = 0  # Not phishing
#                 data.append(features)
#             except Exception as e:
#                 print(f"Error processing {url}: {str(e)}")
        
#         # Process phishing URLs
#         print(f"Processing {len(phishing_urls)} phishing URLs...")
#         for url in phishing_urls:
#             try:
#                 url = url.rstrip('/')
#                 html_content = self.scrape_website(url)
#                 features = self.extract_features(url, html_content)
#                 features['is_phishing'] = 1  # Phishing
#                 data.append(features)
#             except Exception as e:
#                 print(f"Error processing {url}: {str(e)}")
        
#         # Create DataFrame
#         dataset = pd.DataFrame(data)
        
#         # Prepare data
#         X = dataset.drop('is_phishing', axis=1)
#         y = dataset['is_phishing']
        
#         # Check that we have at least two classes
#         class_counts = y.value_counts()
#         if len(class_counts) < 2:
#             raise ValueError(
#                 "The dataset has only one class (all legitimate or all phishing). "
#                 "Please provide data for both classes before training."
#             )
        
#         # Save feature names for later use
#         self.features = X.columns.tolist()
        
#         # Split data
#         X_train, X_test, y_train, y_test = train_test_split(
#             X, y, test_size=test_size, random_state=random_state, stratify=y
#         )
        
#         # Scale data
#         self.scaler.fit(X_train)
#         X_train_scaled = self.scaler.transform(X_train)
#         X_test_scaled = self.scaler.transform(X_test)
        
#         # Train Random Forest with improved hyperparameters
#         print("Training Random Forest model...")
#         self.model_rf = RandomForestClassifier(
#             n_estimators=rf_estimators,
#             max_depth=15,
#             min_samples_split=5,
#             min_samples_leaf=2,
#             max_features='sqrt',
#             class_weight='balanced',
#             random_state=random_state,
#             n_jobs=-1
#         )
#         self.model_rf.fit(X_train_scaled, y_train)
#         rf_pred = self.model_rf.predict(X_test_scaled)
#         rf_accuracy = accuracy_score(y_test, rf_pred)
#         print(f"Random Forest accuracy: {rf_accuracy:.4f}")
        
#         # Train SVM with improved hyperparameters
#         print("Training SVM model...")
#         self.model_svm = SVC(
#             kernel=svm_kernel,
#             C=10,
#             gamma='scale',
#             probability=True,
#             class_weight='balanced',
#             random_state=random_state
#         )
#         self.model_svm.fit(X_train_scaled, y_train)
#         svm_pred = self.model_svm.predict(X_test_scaled)
#         svm_accuracy = accuracy_score(y_test, svm_pred)
#         print(f"SVM accuracy: {svm_accuracy:.4f}")
        
#         # Train Neural Network with improved architecture
#         print("Training Neural Network model...")
#         self.model_nn = tf.keras.Sequential([
#             tf.keras.layers.Dense(128, activation='relu', input_shape=(X_train_scaled.shape[1],)),
#             tf.keras.layers.BatchNormalization(),
#             tf.keras.layers.Dropout(0.3),
#             tf.keras.layers.Dense(64, activation='relu'),
#             tf.keras.layers.BatchNormalization(),
#             tf.keras.layers.Dropout(0.3),
#             tf.keras.layers.Dense(32, activation='relu'),
#             tf.keras.layers.BatchNormalization(),
#             tf.keras.layers.Dropout(0.2),
#             tf.keras.layers.Dense(1, activation='sigmoid')
#         ])
        
#         self.model_nn.compile(
#             optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
#             loss='binary_crossentropy',
#             metrics=['accuracy']
#         )
        
#         # Setup early stopping and learning rate reduction
#         early_stop = tf.keras.callbacks.EarlyStopping(
#             monitor='val_loss',
#             patience=5,
#             restore_best_weights=True
#         )
        
#         lr_reducer = tf.keras.callbacks.ReduceLROnPlateau(
#             monitor='val_loss',
#             factor=0.5,
#             patience=3,
#             min_lr=0.00001
#         )
        
#         # Use class weights to handle imbalanced data
#         class_weight = {0: 1.0, 1: 1.0}
#         if len(class_counts) > 1:
#             ratio = class_counts[0] / class_counts[1]
#             if ratio > 1:
#                 class_weight = {0: 1.0, 1: ratio}
#             else:
#                 class_weight = {0: 1/ratio, 1: 1.0}
        
#         self.model_nn.fit(
#             X_train_scaled, y_train,
#             epochs=nn_epochs,
#             batch_size=32,
#             verbose=0,
#             validation_split=0.2,
#             callbacks=[early_stop, lr_reducer],
#             class_weight=class_weight
#         )
        
#         nn_pred = (self.model_nn.predict(X_test_scaled) > 0.5).astype(int).flatten()
#         nn_accuracy = accuracy_score(y_test, nn_pred)
#         print(f"Neural Network accuracy: {nn_accuracy:.4f}")
        
#         # Calculate confusion matrix
#         rf_proba = self.model_rf.predict_proba(X_test_scaled)[:, 1]
#         svm_proba = self.model_svm.predict_proba(X_test_scaled)[:, 1]
#         nn_proba = self.model_nn.predict(X_test_scaled).flatten()
        
#         # Weighted ensemble
#         ensemble_avg = (0.4 * rf_proba + 0.3 * svm_proba + 0.3 * nn_proba)
#         ensemble_pred = (ensemble_avg > 0.5).astype(int)
#         ensemble_accuracy = accuracy_score(y_test, ensemble_pred)
#         print(f"Ensemble accuracy: {ensemble_accuracy:.4f}")
        
#         cm = confusion_matrix(y_test, ensemble_pred)
        
#         # Calculate precision, recall, F1
#         from sklearn.metrics import precision_score, recall_score, f1_score
#         precision = precision_score(y_test, ensemble_pred)
#         recall = recall_score(y_test, ensemble_pred)
#         f1 = f1_score(y_test, ensemble_pred)
        
#         # Extract feature importance
#         feature_importance = self.model_rf.feature_importances_
        
#         # Save the models
#         self.save_models()
        
#         return {
#             'accuracy': ensemble_accuracy,
#             'precision': precision,
#             'recall': recall,
#             'f1': f1,
#             'confusion_matrix': cm,
#             'feature_importance': feature_importance,
#             'feature_names': self.features
#         }
    
#     def save_models(self, directory='models'):
#         """
#         Save trained models to disk
#         """
#         if not os.path.exists(directory):
#             os.makedirs(directory)
        
#         # Save Random Forest model
#         with open(f"{directory}/model_rf.pkl", 'wb') as f:
#             pickle.dump(self.model_rf, f)
        
#         # Save SVM model
#         with open(f"{directory}/model_svm.pkl", 'wb') as f:
#             pickle.dump(self.model_svm, f)
        
#         # Save Neural Network model in the supported .keras format
#         self.model_nn.save(f"{directory}/model_nn.keras")
        
#         # Save scaler
#         with open(f"{directory}/scaler.pkl", 'wb') as f:
#             pickle.dump(self.scaler, f)
        
#         # Save feature names
#         with open(f"{directory}/features.pkl", 'wb') as f:
#             pickle.dump(self.features, f)
        
#         print(f"Models saved to {directory} directory")
    
#     def load_models(self, directory='models'):
#         """
#         Load trained models from disk
#         """
#         # Load Random Forest model
#         with open(f"{directory}/model_rf.pkl", 'rb') as f:
#             self.model_rf = pickle.load(f)
        
#         # Load SVM model
#         with open(f"{directory}/model_svm.pkl", 'rb') as f:
#             self.model_svm = pickle.load(f)
        
#         # Load Neural Network model
#         self.model_nn = tf.keras.models.load_model(f"{directory}/model_nn.keras")
        
#         # Load scaler
#         with open(f"{directory}/scaler.pkl", 'rb') as f:
#             self.scaler = pickle.load(f)
        
#         # Load feature names
#         with open(f"{directory}/features.pkl", 'rb') as f:
#             self.features = pickle.load(f)
        
#         print("Models loaded successfully")
    
#     def check_url(self, url):
#         """
#         Check if a URL is likely a phishing website
#         """
#         # Normalize trailing slash here too (just in case user input includes a slash)
#         url = url.rstrip('/')

#         html_content = self.scrape_website(url)
#         features = self.extract_features(url, html_content)
        
#         features_df = pd.DataFrame([features])
        
#         # Ensure all required features are present
#         for feature in self.features:
#             if feature not in features_df.columns:
#                 features_df[feature] = 0
        
#         # Ensure we only use features that the model was trained on
#         features_df = features_df[self.features]
#         features_scaled = self.scaler.transform(features_df)
        
#         rf_pred = self.model_rf.predict_proba(features_scaled)[0][1]
#         svm_pred = self.model_svm.predict_proba(features_scaled)[0][1]
#         nn_pred = self.model_nn.predict(features_scaled)[0][0]
        
#         # Weighted ensemble
#         avg_pred = (0.4 * rf_pred + 0.3 * svm_pred + 0.3 * nn_pred)
        
#         # Risk level categorization
#         risk_level = "Low"
#         if avg_pred > 0.75:
#             risk_level = "High"
#         elif avg_pred > 0.5:
#             risk_level = "Medium"
        
#         return {
#             'url': url,
#             'random_forest': rf_pred,
#             'svm': svm_pred,
#             'neural_network': nn_pred,
#             'average': avg_pred,
#             'is_phishing': avg_pred > 0.5,
#             'risk_level': risk_level,
#             'features': features
#         }
    
# # streamlit_app.py code:
# import streamlit as st
# import os
# import pandas as pd
# import numpy as np
# import matplotlib.pyplot as plt
# from phishing_detector import PhishingDetector

# def load_detector():
#     @st.cache_resource
#     def _load_detector():
#         detector = PhishingDetector()
#         required_files = [
#             "models/model_rf.pkl",
#             "models/model_svm.pkl",
#             "models/model_nn.keras",
#             "models/scaler.pkl",
#             "models/features.pkl"
#         ]
#         if all(os.path.exists(file) for file in required_files):
#             detector.load_models()
#             return detector, True
#         else:
#             return detector, False
    
#     detector, models_loaded = _load_detector()
#     if not models_loaded:
#         st.warning("Models not found. Please train the models first using the 'Train Models' tab.")
#     return detector, models_loaded

# def main():
#     st.set_page_config(page_title="Phishing Detection System", page_icon="🛡️", layout="wide")
    
#     st.title("🛡️ Advanced Phishing Detection System")
#     st.markdown("""
#     This application uses machine learning to detect phishing websites with high accuracy. 
#     It employs a weighted ensemble of Random Forest, Support Vector Machine, and Neural Network models.
#     """)
    
#     detector, models_loaded = load_detector()
    
#     # Create four tabs
#     tab1, tab2, tab3 = st.tabs(["Check URL", "Train Models", "About"])
    
#     # ---------------
#     # TAB 1: Check URL
#     # ---------------
#     with tab1:
#         st.header("Check if a URL is a phishing website")
        
#         # Input box and button in a single column
#         url = st.text_input("Enter a URL to check:", "https://example.com")
        
#         if st.button("Check URL", use_container_width=True):
#             if not models_loaded:
#                 st.error("Please train the models first using the 'Train Models' tab.")
#             else:
#                 with st.spinner("Analyzing the URL..."):
#                     try:
#                         # Get the detection results
#                         result = detector.check_url(url)
                        
#                         # Display overall risk info
#                         st.subheader("Phishing Detection Results")
#                         risk_color = "green"
#                         if result['risk_level'] == "Medium":
#                             risk_color = "orange"
#                         elif result['risk_level'] == "High":
#                             risk_color = "red"
                        
#                         st.markdown(f"""
#                         <div style="text-align: center;">
#                             <h3 style="color: {risk_color};">Risk Level: {result['risk_level']}</h3>
#                             <h4>Confidence: {result['average']*100:.1f}%</h4>
#                         </div>
#                         """, unsafe_allow_html=True)
                        
#                         # Simple success/error message
#                         if result['is_phishing']:
#                             st.error("⚠️ The URL is likely a phishing website!")
#                         else:
#                             st.success("✅ The URL appears to be legitimate.")
                        
#                         # Show model predictions in a horizontal bar chart
#                         st.subheader("Model Predictions")
#                         data = {
#                             'Model': ['Random Forest', 'SVM', 'Neural Network', 'Ensemble'],
#                             'Score': [
#                                 result['random_forest'],
#                                 result['svm'],
#                                 result['neural_network'],
#                                 result['average']
#                             ]
#                         }
#                         chart_df = pd.DataFrame(data)
                        
#                         fig, ax = plt.subplots(figsize=(6, 3))
#                         colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728']
#                         ax.barh(chart_df['Model'], chart_df['Score'], color=colors)
#                         ax.set_xlim(0, 1)
#                         ax.set_xlabel('Phishing Score')
#                         ax.axvline(x=0.5, color='red', linestyle='--', alpha=0.5)
#                         plt.tight_layout()
#                         st.pyplot(fig)
                        
#                         # Show key features in a small table
#                         st.subheader("Key Features")
#                         key_features = {
#                             'URL Length': result['features'].get('url_length', 'N/A'),
#                             'Has HTTPS': 'Yes' if result['features'].get('has_https', 0) == 1 else 'No',
#                             'Password Field': 'Yes' if result['features'].get('has_password_field', 0) == 1 else 'No',
#                             'External Redirects': result['features'].get('external_redirects', 'N/A'),
#                             'Suspicious Tags': result['features'].get('num_suspicious_tags', 'N/A'),
#                             'Popup Elements': result['features'].get('popup_count', 'N/A'),
#                             'Hidden Elements': result['features'].get('invisible_elements', 'N/A'),
#                             'Scripts': result['features'].get('num_scripts', 'N/A')
#                         }
#                         key_features_df = pd.DataFrame(list(key_features.items()), columns=['Feature', 'Value'])
#                         st.table(key_features_df)
                        
#                         # Optionally allow user to expand and see all features
#                         with st.expander("View All Features"):
#                             st.json(result['features'])
                    
#                     except Exception as e:
#                         st.error(f"Error checking URL: {str(e)}")

#     # ---------------
#     # TAB 2: Train Models
#     # (unchanged except for small layout improvements if desired)
#     # ---------------
#     with tab2:
#         st.header("Train Phishing Detection Models")
#         st.markdown("""
#         Upload CSV files containing lists of URLs to train the detection models.
        
#         **Requirements:**
#         - CSV files should not have headers
#         - Each row should contain one URL
#         - Include both legitimate and phishing URLs for best results
#         """)
        
#         col1, col2 = st.columns(2)
        
#         with col1:
#             legitimate_file = st.file_uploader("Upload Legitimate URLs CSV", type=["csv"], key="legit")
#             if legitimate_file is not None:
#                 legitimate_preview = pd.read_csv(legitimate_file, header=None)
#                 st.write(f"Legitimate URLs sample ({len(legitimate_preview)} total):")
#                 st.dataframe(legitimate_preview.head(5))
        
#         with col2:
#             phishing_file = st.file_uploader("Upload Phishing URLs CSV", type=["csv"], key="phish")
#             if phishing_file is not None:
#                 phishing_preview = pd.read_csv(phishing_file, header=None)
#                 st.write(f"Phishing URLs sample ({len(phishing_preview)} total):")
#                 st.dataframe(phishing_preview.head(5))
        
#         train_params = st.expander("Training Parameters (Advanced)")
#         with train_params:
#             col1, col2 = st.columns(2)
#             with col1:
#                 test_size = st.slider("Test Split Size", min_value=0.1, max_value=0.5, value=0.2, step=0.05)
#                 rf_estimators = st.slider("Random Forest Estimators", min_value=50, max_value=500, value=100, step=50)
#             with col2:
#                 svm_kernel = st.selectbox("SVM Kernel", options=["rbf", "linear", "poly", "sigmoid"], index=0)
#                 nn_epochs = st.slider("Neural Network Epochs", min_value=10, max_value=100, value=50, step=10)
        
#         if st.button("Train Models", use_container_width=True):
#             if legitimate_file is None or phishing_file is None:
#                 st.error("Please upload both legitimate and phishing URL files.")
#             else:
#                 with st.spinner("Training models. This may take several minutes..."):
#                     try:
#                         # Reset file pointers
#                         legitimate_file.seek(0)
#                         phishing_file.seek(0)
                        
#                         legitimate_urls = pd.read_csv(legitimate_file, header=None)[0].tolist()
#                         phishing_urls = pd.read_csv(phishing_file, header=None)[0].tolist()
                        
#                         # Initialize or load detector
#                         # (already done above, so just use the same detector instance)
                        
#                         # Train the models
#                         training_results = detector.train_models(
#                             legitimate_urls, 
#                             phishing_urls, 
#                             test_size=test_size,
#                             rf_estimators=rf_estimators,
#                             svm_kernel=svm_kernel,
#                             nn_epochs=nn_epochs
#                         )
                        
#                         # Display training results
#                         st.success("Models trained successfully!")
                        
#                         st.subheader("Model Performance")
                        
#                         col1, col2, col3, col4 = st.columns(4)
#                         col1.metric("Accuracy", f"{training_results['accuracy']*100:.1f}%")
#                         col2.metric("Precision", f"{training_results['precision']*100:.1f}%")
#                         col3.metric("Recall", f"{training_results['recall']*100:.1f}%")
#                         col4.metric("F1 Score", f"{training_results['f1']*100:.1f}%")
                        
#                         st.subheader("Confusion Matrix")
#                         cm = training_results['confusion_matrix']
                        
#                         fig, ax = plt.subplots(figsize=(6, 5))
#                         im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
#                         ax.figure.colorbar(im, ax=ax)
#                         ax.set(xticks=[0, 1], yticks=[0, 1],
#                                xticklabels=['Legitimate', 'Phishing'],
#                                yticklabels=['Legitimate', 'Phishing'],
#                                ylabel='True label',
#                                xlabel='Predicted label')
                        
#                         thresh = cm.max() / 2
#                         for i in range(cm.shape[0]):
#                             for j in range(cm.shape[1]):
#                                 ax.text(j, i, format(cm[i, j], 'd'),
#                                         ha="center", va="center",
#                                         color="white" if cm[i, j] > thresh else "black")
                        
#                         plt.tight_layout()
#                         st.pyplot(fig)
                        
#                         if 'feature_importance' in training_results:
#                             st.subheader("Feature Importance")
                            
#                             feat_imp = training_results['feature_importance']
#                             sorted_idx = np.argsort(feat_imp)
#                             feature_names = training_results.get('feature_names', [f'Feature {i}' for i in range(len(feat_imp))])
                            
#                             top_n = min(10, len(sorted_idx))
#                             top_idx = sorted_idx[-top_n:]
                            
#                             fig, ax = plt.subplots(figsize=(8, 6))
#                             ax.barh(range(top_n), feat_imp[top_idx])
#                             ax.set_yticks(range(top_n))
#                             ax.set_yticklabels([feature_names[i] for i in top_idx])
#                             ax.set_xlabel('Feature Importance')
#                             plt.tight_layout()
#                             st.pyplot(fig)
                        
#                     except Exception as e:
#                         st.error(f"Error training models: {str(e)}")
    
#     # ---------------
#     # TAB 3: About
#     # ---------------
#     with tab3:
#         st.header("About This Application")
#         st.markdown("""
#         ### Phishing Detection System
        
#         This application uses machine learning to identify potentially malicious phishing websites
#         by analyzing various features extracted from URLs and their corresponding websites.
        
#         #### How It Works
        
#         1. **URL Analysis**: The system extracts features from the URL itself, such as length, 
#            presence of suspicious characters, domain information, etc.
           
#         2. **Content Analysis**: For accessible websites, the system analyzes the HTML content,
#            looking for suspicious elements like hidden fields, external redirects, and more.
           
#         3. **ML Models**: The system uses a weighted ensemble of multiple models:
#            - Random Forest: Good at handling various feature types
#            - Support Vector Machine: Effective at finding decision boundaries
#            - Neural Network: Capable of learning complex patterns
           
#         4. **Ensemble Decision**: The final verdict is determined by a weighted average of all models,
#            providing more reliable results than any single model.
        
#         #### Limitations
        
#         - The system requires internet access to analyze website content
#         - Some websites may block automated requests
#         - The system works best when trained on recent phishing examples
#         - False positives may occur for legitimate but unusual websites
#         """)

# if __name__ == "__main__":
#     main()

# --------------------------------------------------------------------- OLDER CODE BELOW (FIRST VERSION) ------------------------------------------------------------------------------------------

# PHISHING_DETECTOR.py:

# import requests 
# import urllib3
# import pandas as pd
# import numpy as np
# import re
# from bs4 import BeautifulSoup
# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import StandardScaler
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.svm import SVC
# from sklearn.metrics import accuracy_score, confusion_matrix, roc_curve, precision_recall_curve
# import tensorflow as tf
# from sklearn.decomposition import PCA
# import matplotlib.pyplot as plt
# import pickle
# import os
# import warnings

# # Disable SSL warnings to allow scraping of potential phishing sites
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# warnings.filterwarnings('ignore')

# class PhishingDetector:
#     def __init__(self):
#         self.model_rf = None
#         self.model_svm = None
#         self.model_nn = None
#         self.scaler = StandardScaler()
#         self.features = []
        
#     def scrape_website(self, url):
#         """
#         Scrape the website content from a given URL
#         """
#         try:
#             headers = {
#                 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
#             }
#             response = requests.get(url, headers=headers, verify=False, timeout=10)
#             html_content = response.text
#             return html_content
#         except Exception as e:
#             print(f"Error scraping {url}: {str(e)}")
#             return None
    
#     def extract_features(self, url, html_content=None):
#         """
#         Extract features from URL and HTML content
#         """
#         # Normalize trailing slash so "https://google.com/" == "https://google.com"
#         url = url.rstrip('/')

#         features = {}
        
#         # URL features
#         features['url_length'] = len(url)
#         features['num_dots'] = url.count('.')
#         features['num_hyphens'] = url.count('-')
#         features['num_underscores'] = url.count('_')
#         features['num_slashes'] = url.count('/')
#         features['num_question_marks'] = url.count('?')
#         features['num_equal_signs'] = url.count('=')
#         features['num_at_symbols'] = url.count('@')
#         features['num_ampersands'] = url.count('&')
#         features['has_https'] = 1 if url.startswith('https://') else 0
        
#         # If HTML content was not successfully retrieved, fill HTML features with zeros
#         if html_content is None:
#             features['num_iframes'] = 0
#             features['num_scripts'] = 0
#             features['num_links'] = 0
#             features['num_suspicious_tags'] = 0
#             features['num_forms'] = 0
#             features['num_images'] = 0
#             features['has_password_field'] = 0
#             features['external_redirects'] = 0
#             return features
            
#         # Parse HTML content
#         soup = BeautifulSoup(html_content, 'html.parser')
        
#         # HTML features
#         features['num_iframes'] = len(soup.find_all('iframe'))
#         features['num_scripts'] = len(soup.find_all('script'))
#         features['num_links'] = len(soup.find_all('a'))
        
#         # Count suspicious HTML tags (often used in phishing)
#         suspicious_tags = ['form', 'input', 'button', 'select', 'textarea']
#         features['num_suspicious_tags'] = sum(len(soup.find_all(tag)) for tag in suspicious_tags)
        
#         # Forms and password fields
#         features['num_forms'] = len(soup.find_all('form'))
#         features['has_password_field'] = 1 if soup.find('input', {'type': 'password'}) else 0
        
#         # Images
#         features['num_images'] = len(soup.find_all('img'))
        
#         # External redirects in links
#         external_redirects = 0
#         domain = re.findall(r'://([^/]+)/?', url)
#         domain = domain[0] if domain else ""
        
#         for link in soup.find_all('a', href=True):
#             href = link['href']
#             if href.startswith('http') and domain not in href:
#                 external_redirects += 1
        
#         features['external_redirects'] = external_redirects
        
#         return features
    
#     def create_dataset(self, legitimate_urls_file, phishing_urls_file, output_file='phishing_dataset.csv'):
#         """
#         Create a dataset from lists of legitimate and phishing URLs
#         """
#         # Load URLs
#         legitimate_urls = pd.read_csv(legitimate_urls_file, header=None)[0].tolist()
#         phishing_urls = pd.read_csv(phishing_urls_file, header=None)[0].tolist()
        
#         data = []
        
#         # Process legitimate URLs
#         print(f"Processing {len(legitimate_urls)} legitimate URLs...")
#         for url in legitimate_urls:
#             try:
#                 # Optionally remove trailing slash from CSV data as well
#                 url = url.rstrip('/')
                
#                 html_content = self.scrape_website(url)
#                 features = self.extract_features(url, html_content)
#                 features['is_phishing'] = 0  # Not phishing
#                 data.append(features)
#             except Exception as e:
#                 print(f"Error processing {url}: {str(e)}")
        
#         # Process phishing URLs
#         print(f"Processing {len(phishing_urls)} phishing URLs...")
#         for url in phishing_urls:
#             try:
#                 # Optionally remove trailing slash
#                 url = url.rstrip('/')
                
#                 html_content = self.scrape_website(url)
#                 features = self.extract_features(url, html_content)
#                 features['is_phishing'] = 1  # Phishing
#                 data.append(features)
#             except Exception as e:
#                 print(f"Error processing {url}: {str(e)}")
        
#         # Create DataFrame and save to CSV
#         df = pd.DataFrame(data)
#         df.to_csv(output_file, index=False)
#         print(f"Dataset created and saved to {output_file}")
#         return df
    
#     def load_or_create_dataset(self, legitimate_urls_file, phishing_urls_file, output_file='phishing_dataset.csv'):
#         """
#         Load dataset if it exists, otherwise create it
#         """
#         if os.path.exists(output_file):
#             print(f"Loading existing dataset from {output_file}")
#             return pd.read_csv(output_file)
#         else:
#             return self.create_dataset(legitimate_urls_file, phishing_urls_file, output_file)
    
#     def train_models(self, dataset, test_size=0.2, random_state=42):
#         """
#         Train the machine learning models on the dataset and generate visualizations.
#         """
#         # Prepare data
#         X = dataset.drop('is_phishing', axis=1)
#         y = dataset['is_phishing']
        
#         # Check that we have at least two classes
#         class_counts = y.value_counts()
#         if len(class_counts) < 2:
#             raise ValueError(
#                 "The dataset has only one class (all legitimate or all phishing). "
#                 "Please provide data for both classes before training."
#             )
        
#         # Save feature names for later use
#         self.features = X.columns.tolist()
        
#         # Split data
#         X_train, X_test, y_train, y_test = train_test_split(
#             X, y, test_size=test_size, random_state=random_state
#         )
        
#         # Scale data
#         self.scaler.fit(X_train)
#         X_train_scaled = self.scaler.transform(X_train)
#         X_test_scaled = self.scaler.transform(X_test)
        
#         # Train Random Forest
#         print("Training Random Forest model...")
#         self.model_rf = RandomForestClassifier(n_estimators=100, random_state=random_state, n_jobs=-1)
#         self.model_rf.fit(X_train_scaled, y_train)
#         rf_pred = self.model_rf.predict(X_test_scaled)
#         rf_accuracy = accuracy_score(y_test, rf_pred)
#         print(f"Random Forest accuracy: {rf_accuracy:.4f}")
        
#         # Train SVM
#         print("Training SVM model...")
#         self.model_svm = SVC(probability=True, random_state=random_state)
#         self.model_svm.fit(X_train_scaled, y_train)
#         svm_pred = self.model_svm.predict(X_test_scaled)
#         svm_accuracy = accuracy_score(y_test, svm_pred)
#         print(f"SVM accuracy: {svm_accuracy:.4f}")
        
#         # Train Neural Network with Early Stopping
#         print("Training Neural Network model...")
#         self.model_nn = tf.keras.Sequential([
#             tf.keras.layers.Dense(64, activation='relu', input_shape=(X_train_scaled.shape[1],)),
#             tf.keras.layers.Dropout(0.2),
#             tf.keras.layers.Dense(32, activation='relu'),
#             tf.keras.layers.Dropout(0.2),
#             tf.keras.layers.Dense(1, activation='sigmoid')
#         ])
        
#         self.model_nn.compile(
#             optimizer='adam',
#             loss='binary_crossentropy',
#             metrics=['accuracy']
#         )
        
#         early_stop = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=3)
#         self.model_nn.fit(
#             X_train_scaled, y_train,
#             epochs=20,
#             batch_size=32,
#             verbose=0,
#             validation_split=0.1,
#             callbacks=[early_stop]
#         )
        
#         nn_pred = (self.model_nn.predict(X_test_scaled) > 0.5).astype(int).flatten()
#         nn_accuracy = accuracy_score(y_test, nn_pred)
#         print(f"Neural Network accuracy: {nn_accuracy:.4f}")
        
#         # Visualize dataset with PCA (3D plot)
#         pca = PCA(n_components=3)
#         X_pca = pca.fit_transform(X)
        
#         fig = plt.figure(figsize=(10, 8))
#         ax = fig.add_subplot(111, projection='3d')
        
#         legitimate = X_pca[y == 0]
#         phishing = X_pca[y == 1]
        
#         ax.scatter(legitimate[:, 0], legitimate[:, 1], legitimate[:, 2], c='blue', label='Legitimate')
#         ax.scatter(phishing[:, 0], phishing[:, 1], phishing[:, 2], c='red', label='Phishing')
        
#         ax.set_title('3D PCA of Website Features')
#         ax.set_xlabel('PC1')
#         ax.set_ylabel('PC2')
#         ax.set_zlabel('PC3')
#         ax.legend()
        
#         plt.savefig('pca_visualization.png')
#         plt.close()
#         print("PCA visualization saved to pca_visualization.png")
        
#         # --- Additional Visualizations ---

#         # 1. Confusion Matrix for Ensemble Prediction
#         rf_proba = self.model_rf.predict_proba(X_test_scaled)[:, 1]
#         svm_proba = self.model_svm.predict_proba(X_test_scaled)[:, 1]
#         nn_proba = self.model_nn.predict(X_test_scaled).flatten()
#         ensemble_avg = (rf_proba + svm_proba + nn_proba) / 3
#         ensemble_pred = (ensemble_avg > 0.5).astype(int)
#         cm = confusion_matrix(y_test, ensemble_pred)
#         plt.figure(figsize=(6, 5))
#         plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
#         plt.title('Confusion Matrix (Ensemble)')
#         plt.colorbar()
#         tick_marks = np.arange(2)
#         plt.xticks(tick_marks, ['Legitimate', 'Phishing'], rotation=45)
#         plt.yticks(tick_marks, ['Legitimate', 'Phishing'])
#         thresh = cm.max() / 2.
#         for i, j in np.ndindex(cm.shape):
#             plt.text(j, i, format(cm[i, j], 'd'),
#                      horizontalalignment="center",
#                      color="white" if cm[i, j] > thresh else "black")
#         plt.ylabel('True label')
#         plt.xlabel('Predicted label')
#         plt.tight_layout()
#         plt.savefig('confusion_matrix.png')
#         plt.close()
#         print("Confusion matrix saved to confusion_matrix.png")
        
#         # 2. Feature Importance from Random Forest
#         importances = self.model_rf.feature_importances_
#         indices = np.argsort(importances)[::-1]
#         plt.figure(figsize=(10, 6))
#         plt.title("Feature Importances (Random Forest)")
#         plt.bar(range(len(importances)), importances[indices], align="center")
#         plt.xticks(range(len(importances)), [self.features[i] for i in indices], rotation=45)
#         plt.ylabel("Importance")
#         plt.tight_layout()
#         plt.savefig('feature_importance.png')
#         plt.close()
#         print("Feature importance plot saved to feature_importance.png")
        
#         # 3. Feature Correlation Heatmap
#         plt.figure(figsize=(10, 8))
#         correlation_matrix = dataset.drop('is_phishing', axis=1).corr()
#         plt.imshow(correlation_matrix, interpolation='nearest', cmap=plt.cm.RdBu)
#         plt.title("Feature Correlation")
#         plt.colorbar()
#         ticks = np.arange(len(correlation_matrix.columns))
#         plt.xticks(ticks, correlation_matrix.columns, rotation=90)
#         plt.yticks(ticks, correlation_matrix.columns)
#         plt.tight_layout()
#         plt.savefig('feature_correlation.png')
#         plt.close()
#         print("Feature correlation plot saved to feature_correlation.png")
        
#         return {
#             'RandomForest': rf_accuracy,
#             'SVM': svm_accuracy,
#             'NeuralNetwork': nn_accuracy
#         }
    
#     def save_models(self, directory='models'):
#         """
#         Save trained models to disk
#         """
#         if not os.path.exists(directory):
#             os.makedirs(directory)
        
#         # Save Random Forest model
#         with open(f"{directory}/model_rf.pkl", 'wb') as f:
#             pickle.dump(self.model_rf, f)
        
#         # Save SVM model
#         with open(f"{directory}/model_svm.pkl", 'wb') as f:
#             pickle.dump(self.model_svm, f)
        
#         # Save Neural Network model in the supported .keras format
#         self.model_nn.save(f"{directory}/model_nn.keras")
        
#         # Save scaler
#         with open(f"{directory}/scaler.pkl", 'wb') as f:
#             pickle.dump(self.scaler, f)
        
#         # Save feature names
#         with open(f"{directory}/features.pkl", 'wb') as f:
#             pickle.dump(self.features, f)
        
#         print(f"Models saved to {directory} directory")
    
#     def load_models(self, directory='models'):
#         """
#         Load trained models from disk
#         """
#         # Load Random Forest model
#         with open(f"{directory}/model_rf.pkl", 'rb') as f:
#             self.model_rf = pickle.load(f)
        
#         # Load SVM model
#         with open(f"{directory}/model_svm.pkl", 'rb') as f:
#             self.model_svm = pickle.load(f)
        
#         # Load Neural Network model
#         self.model_nn = tf.keras.models.load_model(f"{directory}/model_nn.keras")
        
#         # Load scaler
#         with open(f"{directory}/scaler.pkl", 'rb') as f:
#             self.scaler = pickle.load(f)
        
#         # Load feature names
#         with open(f"{directory}/features.pkl", 'rb') as f:
#             self.features = pickle.load(f)
        
#         print("Models loaded successfully")
    
#     def check_url(self, url):
#         """
#         Check if a URL is likely a phishing website
#         """
#         # Normalize trailing slash here too (just in case user input includes a slash)
#         url = url.rstrip('/')

#         html_content = self.scrape_website(url)
#         features = self.extract_features(url, html_content)
        
#         features_df = pd.DataFrame([features])
        
#         for feature in self.features:
#             if feature not in features_df.columns:
#                 features_df[feature] = 0
        
#         features_df = features_df[self.features]
#         features_scaled = self.scaler.transform(features_df)
        
#         rf_pred = self.model_rf.predict_proba(features_scaled)[0][1]
#         svm_pred = self.model_svm.predict_proba(features_scaled)[0][1]
#         nn_pred = self.model_nn.predict(features_scaled)[0][0]
        
#         avg_pred = (rf_pred + svm_pred + nn_pred) / 3
        
#         return {
#             'url': url,
#             'random_forest': rf_pred,
#             'svm': svm_pred,
#             'neural_network': nn_pred,
#             'average': avg_pred,
#             'is_phishing': avg_pred > 0.5,
#             'features': features
#         }

# STREAMLIT_APP.py: ---------------------------------------------------------------------------------------------------------------------------------

# import streamlit as st
# import os
# from phishing_detector import PhishingDetector

# def load_detector():
#     @st.cache_resource
#     def _load_detector():
#         detector = PhishingDetector()
#         required_files = [
#             "models/model_rf.pkl",
#             "models/model_svm.pkl",
#             "models/model_nn.keras",
#             "models/scaler.pkl",
#             "models/features.pkl"
#         ]
#         if all(os.path.exists(file) for file in required_files):
#             detector.load_models()
#         else:
#             st.warning("Models not found. Please train the models first.")
#         return detector
#     return _load_detector()

# def main():
#     st.set_page_config(page_title="Phishing Detection System", page_icon="🛡️", layout="wide")
    
#     st.title("🛡️ Phishing Detection System")
#     st.markdown("""
#     This application uses machine learning to detect phishing websites. 
#     It employs a combination of Random Forest, Support Vector Machine, and Neural Network models.
#     """)
    
#     detector = load_detector()
    
#     tab1, tab2, tab3 = st.tabs(["Check URL", "Train Models", "About"])
    
#     with tab1:
#         st.header("Check if a URL is a phishing website")
#         url = st.text_input("Enter a URL to check:", "https://example.com")
        
#         if st.button("Check URL"):
#             with st.spinner("Analyzing the URL..."):
#                 try:
#                     result = detector.check_url(url)
#                     st.subheader("Results")
#                     st.write(f"**Random Forest Prediction:** {result['random_forest']:.4f}")
#                     st.write(f"**SVM Prediction:** {result['svm']:.4f}")
#                     st.write(f"**Neural Network Prediction:** {result['neural_network']:.4f}")
#                     st.write(f"**Average Prediction:** {result['average']:.4f}")
#                     if result['is_phishing']:
#                         st.error("The URL is likely a phishing website!")
#                     else:
#                         st.success("The URL appears to be legitimate.")
#                     st.json(result['features'])
#                 except Exception as e:
#                     st.error(f"Error checking URL: {str(e)}")
    
#     with tab2:
#         st.header("Train Phishing Detection Models")
#         st.markdown("Upload CSV files containing lists of URLs. The CSV files should not have headers and should contain one URL per line.")
        
#         legitimate_file = st.file_uploader("Upload Legitimate URLs CSV", type=["csv"], key="legit")
#         phishing_file = st.file_uploader("Upload Phishing URLs CSV", type=["csv"], key="phish")
        
#         if legitimate_file is not None and phishing_file is not None:
#             if st.button("Train Models"):
#                 try:
#                     for filename in ["legitimate_urls.csv", "phishing_urls.csv"]:
#                         if os.path.exists(filename):
#                             os.remove(filename)
                    
#                     with open("legitimate_urls.csv", "wb") as f:
#                         f.write(legitimate_file.getbuffer())
#                     with open("phishing_urls.csv", "wb") as f:
#                         f.write(phishing_file.getbuffer())
                    
#                     dataset = detector.load_or_create_dataset("legitimate_urls.csv", "phishing_urls.csv")
                    
#                     st.write("Class distribution in dataset:")
#                     st.write(dataset['is_phishing'].value_counts())
                    
#                     accuracies = detector.train_models(dataset)
#                     detector.save_models()
                    
#                     st.success("Models trained and saved successfully!")
#                     st.write("### Model Accuracies")
#                     st.write(f"**Random Forest:** {accuracies['RandomForest']:.4f}")
#                     st.write(f"**SVM:** {accuracies['SVM']:.4f}")
#                     st.write(f"**Neural Network:** {accuracies['NeuralNetwork']:.4f}")
                    
#                     st.image("pca_visualization.png", caption="PCA Visualization")
#                     st.image("confusion_matrix.png", caption="Confusion Matrix (Ensemble)")
#                     st.image("feature_importance.png", caption="Feature Importance (Random Forest)")
#                     st.image("feature_correlation.png", caption="Feature Correlation")
#                 except Exception as e:
#                     st.error(f"Error during training: {str(e)}")
    
#     with tab3:
#         st.header("About")
#         st.markdown("""
#         This phishing detection system is designed to help identify malicious websites by analyzing both URL-based and HTML-based features.
#         The system uses a combination of machine learning models:
#         - **Random Forest**
#         - **Support Vector Machine (SVM)**
#         - **Neural Network**

#         The application scrapes website content, extracts features, and then applies these models to determine the likelihood that a website is phishing.
#         """)
    
# if __name__ == '__main__':
#     main()