import requests
import urllib3
import pandas as pd
import numpy as np
import re
import itertools
from bs4 import BeautifulSoup
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, confusion_matrix, roc_curve, precision_recall_curve
import tensorflow as tf
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import pickle
import os
import warnings
import tldextract
from urllib.parse import urlparse

# Disable SSL warnings to allow scraping of potential phishing sites
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

class PhishingDetector:
    def __init__(self):
        self.model_rf = None
        self.model_svm = None
        self.model_nn = None
        self.scaler = StandardScaler()
        self.features = []
        
    def scrape_website(self, url):
        """
        Scrape the website content from a given URL with improved reliability
        """
        try:
            # More realistic user agent
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'DNT': '1',
            }
            
            # Use a timeout to prevent hanging on slow sites
            response = requests.get(url, headers=headers, verify=False, timeout=10)
            
            # Check if response is successful
            if response.status_code == 200:
                html_content = response.text
                return html_content
            else:
                print(f"Failed to retrieve {url}: Status code {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            print(f"Timeout occurred while scraping {url}")
            return None
        except requests.exceptions.TooManyRedirects:
            print(f"Too many redirects for {url}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Error scraping {url}: {str(e)}")
            return None
    
    def extract_features(self, url, html_content=None):
        """
        Extract features from URL and HTML content with improved detection capabilities
        """
        # Normalize trailing slash so "https://google.com/" == "https://google.com"
        url = url.rstrip('/')

        features = {}
        
        # Parse URL components
        parsed_url = urlparse(url)
        domain_info = tldextract.extract(url)
        
        # URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain_info.domain)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['has_https'] = 1 if url.startswith('https://') else 0
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_parameters'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
        features['uses_ip_address'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_info.domain) else 0
        features['suspicious_tld'] = 1 if domain_info.suffix in ['xyz', 'top', 'ml', 'ga', 'cf', 'gq', 'tk'] else 0
        features['domain_age_days'] = 0  # Placeholder - could be implemented with WHOIS API
        
        # If HTML content was not successfully retrieved, fill HTML features with zeros
        if html_content is None:
            features['num_iframes'] = 0
            features['num_scripts'] = 0
            features['num_links'] = 0
            features['num_suspicious_tags'] = 0
            features['num_forms'] = 0
            features['num_images'] = 0
            features['has_password_field'] = 0
            features['external_redirects'] = 0
            features['invisible_elements'] = 0
            features['popup_count'] = 0
            features['tiny_text'] = 0
            features['favicon_mismatch'] = 0
            features['has_login_form'] = 0
            features['has_submit_button'] = 0
            features['obfuscated_js'] = 0
            return features
            
        # Parse HTML content
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # HTML features
        features['num_iframes'] = len(soup.find_all('iframe'))
        features['num_scripts'] = len(soup.find_all('script'))
        features['num_links'] = len(soup.find_all('a'))
        
        # Count suspicious HTML tags (often used in phishing)
        suspicious_tags = ['form', 'input', 'button', 'select', 'textarea', 'meta', 'link', 'embed', 'object']
        features['num_suspicious_tags'] = sum(len(soup.find_all(tag)) for tag in suspicious_tags)
        
        # Forms and password fields
        forms = soup.find_all('form')
        features['num_forms'] = len(forms)
        features['has_password_field'] = 1 if soup.find('input', {'type': 'password'}) else 0
        features['has_login_form'] = 1 if soup.find('form') and soup.find('input', {'type': 'password'}) else 0
        features['has_submit_button'] = 1 if soup.find('button', {'type': 'submit'}) or soup.find('input', {'type': 'submit'}) else 0
        
        # Images
        images = soup.find_all('img')
        features['num_images'] = len(images)
        
        # Check for tiny text (potential hidden content)
        tiny_text_elements = soup.find_all(style=re.compile(r'font-size:\s*[0-1]px|visibility:\s*hidden|display:\s*none'))
        features['tiny_text'] = len(tiny_text_elements)
        
        # Check for invisible elements
        invisible_elements = soup.find_all(style=re.compile(r'opacity:\s*0|visibility:\s*hidden|display:\s*none'))
        features['invisible_elements'] = len(invisible_elements)
        
        # Check for popups
        popup_elements = soup.find_all(lambda tag: tag.name == 'script' and 
                                      ('window.open' in tag.text or 'popup' in tag.text or 'alert(' in tag.text))
        features['popup_count'] = len(popup_elements)
        
        # Check for favicon mismatch (common in phishing)
        favicon_links = soup.find_all('link', rel='icon') + soup.find_all('link', rel='shortcut icon')
        features['favicon_mismatch'] = 0
        if favicon_links:
            for link in favicon_links:
                if 'href' in link.attrs:
                    favicon_url = link['href']
                    if favicon_url.startswith('http') and domain_info.domain not in favicon_url:
                        features['favicon_mismatch'] = 1
                        break
        
        # External redirects in links
        external_redirects = 0
        domain = domain_info.domain
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http') and domain not in href:
                external_redirects += 1
        
        features['external_redirects'] = external_redirects
        
        # Check for obfuscated JavaScript
        obfuscated_js = 0
        for script in soup.find_all('script'):
            if script.string and any(x in script.string for x in ['eval(', 'unescape(', 'fromCharCode', 'String.fromCharCode']):
                obfuscated_js += 1
        features['obfuscated_js'] = obfuscated_js
        
        return features
    
    def create_dataset(self, legitimate_urls_file, phishing_urls_file, output_file='phishing_dataset.csv'):
        """
        Create a dataset from lists of legitimate and phishing URLs
        """
        # Load URLs
        legitimate_urls = pd.read_csv(legitimate_urls_file, header=None)[0].tolist()
        phishing_urls = pd.read_csv(phishing_urls_file, header=None)[0].tolist()
        
        data = []
        
        # Process legitimate URLs
        print(f"Processing {len(legitimate_urls)} legitimate URLs...")
        for url in legitimate_urls:
            try:
                url = url.rstrip('/')
                html_content = self.scrape_website(url)
                features = self.extract_features(url, html_content)
                features['is_phishing'] = 0  # Not phishing
                data.append(features)
            except Exception as e:
                print(f"Error processing {url}: {str(e)}")
        
        # Process phishing URLs
        print(f"Processing {len(phishing_urls)} phishing URLs...")
        for url in phishing_urls:
            try:
                url = url.rstrip('/')
                html_content = self.scrape_website(url)
                features = self.extract_features(url, html_content)
                features['is_phishing'] = 1  # Phishing
                data.append(features)
            except Exception as e:
                print(f"Error processing {url}: {str(e)}")
        
        # Create DataFrame and save to CSV
        df = pd.DataFrame(data)
        df.to_csv(output_file, index=False)
        print(f"Dataset created and saved to {output_file}")
        return df
    
    def load_or_create_dataset(self, legitimate_urls_file, phishing_urls_file, output_file='phishing_dataset.csv'):
        """
        Load dataset if it exists, otherwise create it
        """
        if os.path.exists(output_file):
            print(f"Loading existing dataset from {output_file}")
            return pd.read_csv(output_file)
        else:
            return self.create_dataset(legitimate_urls_file, phishing_urls_file, output_file)
    
    def train_models(self, legitimate_urls, phishing_urls, test_size=0.2, random_state=42, rf_estimators=200, svm_kernel='rbf', nn_epochs=50):
        """
        Train the machine learning models with the given URLs and parameters.
        Also creates and saves a 3D PCA plot of the entire dataset.
        """
        # Create dataset from URLs
        print("Creating dataset from URLs...")
        data = []
        
        # Process legitimate URLs
        print(f"Processing {len(legitimate_urls)} legitimate URLs...")
        for url in legitimate_urls:
            try:
                url = url.rstrip('/')
                html_content = self.scrape_website(url)
                features = self.extract_features(url, html_content)
                features['is_phishing'] = 0  # Not phishing
                data.append(features)
            except Exception as e:
                print(f"Error processing {url}: {str(e)}")
        
        # Process phishing URLs
        print(f"Processing {len(phishing_urls)} phishing URLs...")
        for url in phishing_urls:
            try:
                url = url.rstrip('/')
                html_content = self.scrape_website(url)
                features = self.extract_features(url, html_content)
                features['is_phishing'] = 1  # Phishing
                data.append(features)
            except Exception as e:
                print(f"Error processing {url}: {str(e)}")
        
        # Create DataFrame
        dataset = pd.DataFrame(data)
        
        # Prepare data
        X = dataset.drop('is_phishing', axis=1)
        y = dataset['is_phishing']
        
        # Check that we have at least two classes
        class_counts = y.value_counts()
        if len(class_counts) < 2:
            raise ValueError(
                "The dataset has only one class (all legitimate or all phishing). "
                "Please provide data for both classes before training."
            )
        
        # -------------------------------
        # 3D PCA Visualization
        # -------------------------------
        # We do a separate scaler for PCA so we can visualize the entire dataset
        scaler_for_pca = StandardScaler()
        X_scaled_for_pca = scaler_for_pca.fit_transform(X)

        pca = PCA(n_components=3)
        X_pca = pca.fit_transform(X_scaled_for_pca)

        # Plot the 3D PCA scatter
        fig = plt.figure(figsize=(8, 6))
        ax = fig.add_subplot(111, projection='3d')
        
        # Plot legitimate (y=0) in blue, phishing (y=1) in green
        ax.scatter(
            X_pca[y == 0, 0],
            X_pca[y == 0, 1],
            X_pca[y == 0, 2],
            c='blue',
            alpha=0.5,
            label='Legitimate'
        )
        ax.scatter(
            X_pca[y == 1, 0],
            X_pca[y == 1, 1],
            X_pca[y == 1, 2],
            c='green',
            alpha=0.5,
            label='Phishing'
        )
        
        ax.set_xlabel("PC1")
        ax.set_ylabel("PC2")
        ax.set_zlabel("PC3")
        ax.legend()
        plt.title("3D PCA Visualization of Dataset")
        
        # Make sure the 'images' folder exists, then save the PCA plot
        os.makedirs('images', exist_ok=True)
        pca_plot_path = os.path.join('images', 'pca_3d_dataset.png')
        fig.savefig(pca_plot_path)
        plt.close(fig)
        print(f"Saved PCA 3D plot to {pca_plot_path}")
        # -------------------------------
        
        # Now do the normal ML training
        self.features = X.columns.tolist()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Scale data for model training
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        print("Training Random Forest model...")
        self.model_rf = RandomForestClassifier(
            n_estimators=rf_estimators,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            class_weight='balanced',
            random_state=random_state,
            n_jobs=-1
        )
        self.model_rf.fit(X_train_scaled, y_train)
        rf_pred = self.model_rf.predict(X_test_scaled)
        rf_accuracy = accuracy_score(y_test, rf_pred)
        print(f"Random Forest accuracy: {rf_accuracy:.4f}")
        
        # Train SVM
        print("Training SVM model...")
        self.model_svm = SVC(
            kernel=svm_kernel,
            C=10,
            gamma='scale',
            probability=True,
            class_weight='balanced',
            random_state=random_state
        )
        self.model_svm.fit(X_train_scaled, y_train)
        svm_pred = self.model_svm.predict(X_test_scaled)
        svm_accuracy = accuracy_score(y_test, svm_pred)
        print(f"SVM accuracy: {svm_accuracy:.4f}")
        
        # Train Neural Network
        print("Training Neural Network model...")
        self.model_nn = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu', input_shape=(X_train_scaled.shape[1],)),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        self.model_nn.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        early_stop = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )
        
        lr_reducer = tf.keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=3,
            min_lr=0.00001
        )
        
        # Handle class imbalance
        class_weight_dict = {0: 1.0, 1: 1.0}
        if len(class_counts) > 1:
            ratio = class_counts[0] / class_counts[1]
            if ratio > 1:
                class_weight_dict = {0: 1.0, 1: ratio}
            else:
                class_weight_dict = {0: 1/ratio, 1: 1.0}
        
        self.model_nn.fit(
            X_train_scaled, y_train,
            epochs=nn_epochs,
            batch_size=32,
            verbose=0,
            validation_split=0.2,
            callbacks=[early_stop, lr_reducer],
            class_weight=class_weight_dict
        )
        
        nn_pred = (self.model_nn.predict(X_test_scaled) > 0.5).astype(int).flatten()
        nn_accuracy = accuracy_score(y_test, nn_pred)
        print(f"Neural Network accuracy: {nn_accuracy:.4f}")
        
        # Ensemble predictions
        rf_proba = self.model_rf.predict_proba(X_test_scaled)[:, 1]
        svm_proba = self.model_svm.predict_proba(X_test_scaled)[:, 1]
        nn_proba = self.model_nn.predict(X_test_scaled).flatten()
        
        ensemble_avg = (0.4 * rf_proba + 0.3 * svm_proba + 0.3 * nn_proba)
        ensemble_pred = (ensemble_avg > 0.5).astype(int)
        ensemble_accuracy = accuracy_score(y_test, ensemble_pred)
        print(f"Ensemble accuracy: {ensemble_accuracy:.4f}")
        
        cm = confusion_matrix(y_test, ensemble_pred)
        
        # Save the confusion matrix plot
        os.makedirs('images', exist_ok=True)
        fig_cm, ax_cm = plt.subplots(figsize=(6, 5))
        im = ax_cm.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
        ax_cm.figure.colorbar(im, ax=ax_cm)
        ax_cm.set(xticks=[0, 1],
                yticks=[0, 1],
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'],
                ylabel='True label',
                xlabel='Predicted label')
        thresh = cm.max() / 2
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax_cm.text(j, i, format(cm[i, j], 'd'),
                        ha="center", va="center",
                        color="white" if cm[i, j] > thresh else "black")
        fig_cm.tight_layout()
        cm_plot_path = os.path.join('images', 'confusion_matrix.png')
        fig_cm.savefig(cm_plot_path)
        plt.close(fig_cm)
        print(f"Saved confusion matrix to {cm_plot_path}")
        
        from sklearn.metrics import precision_score, recall_score, f1_score
        precision = precision_score(y_test, ensemble_pred)
        recall = recall_score(y_test, ensemble_pred)
        f1 = f1_score(y_test, ensemble_pred)
        
        # Feature importance from Random Forest
        feature_importance = self.model_rf.feature_importances_
        
        # Save feature importance plot
        fig_fi, ax_fi = plt.subplots(figsize=(8, 6))
        indices = range(len(feature_importance))
        ax_fi.barh(indices, feature_importance)
        ax_fi.set_yticks(indices)
        ax_fi.set_yticklabels(self.features)
        ax_fi.set_xlabel('Feature Importance')
        ax_fi.set_title('Random Forest Feature Importance')
        fig_fi.tight_layout()
        fi_plot_path = os.path.join('images', 'feature_importance.png')
        fig_fi.savefig(fi_plot_path)
        plt.close(fig_fi)
        print(f"Saved feature importance plot to {fi_plot_path}")
        
        # Save models
        self.save_models()
        
        return {
            'accuracy': ensemble_accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'confusion_matrix': cm,
            'feature_importance': feature_importance,
            'feature_names': self.features
        }
    
    def save_models(self, directory='models'):
        """
        Save trained models to disk
        """
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        # Save Random Forest model
        with open(f"{directory}/model_rf.pkl", 'wb') as f:
            pickle.dump(self.model_rf, f)
        
        # Save SVM model
        with open(f"{directory}/model_svm.pkl", 'wb') as f:
            pickle.dump(self.model_svm, f)
        
        # Save Neural Network model in the supported .keras format
        self.model_nn.save(f"{directory}/model_nn.keras")
        
        # Save scaler
        with open(f"{directory}/scaler.pkl", 'wb') as f:
            pickle.dump(self.scaler, f)
        
        # Save feature names
        with open(f"{directory}/features.pkl", 'wb') as f:
            pickle.dump(self.features, f)
        
        print(f"Models saved to {directory} directory")
    
    def load_models(self, directory='models'):
        """
        Load trained models from disk
        """
        # Load Random Forest model
        with open(f"{directory}/model_rf.pkl", 'rb') as f:
            self.model_rf = pickle.load(f)
        
        # Load SVM model
        with open(f"{directory}/model_svm.pkl", 'rb') as f:
            self.model_svm = pickle.load(f)
        
        # Load Neural Network model
        self.model_nn = tf.keras.models.load_model(f"{directory}/model_nn.keras")
        
        # Load scaler
        with open(f"{directory}/scaler.pkl", 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Load feature names
        with open(f"{directory}/features.pkl", 'rb') as f:
            self.features = pickle.load(f)
        
        print("Models loaded successfully")
    
    def check_url(self, url):
        """
        Check if a URL is likely a phishing website
        """
        url = url.rstrip('/')
        html_content = self.scrape_website(url)
        features = self.extract_features(url, html_content)
        
        features_df = pd.DataFrame([features])
        
        # Ensure all required features are present
        for feature in self.features:
            if feature not in features_df.columns:
                features_df[feature] = 0
        
        # Ensure we only use features that the model was trained on
        features_df = features_df[self.features]
        features_scaled = self.scaler.transform(features_df)
        
        rf_pred = self.model_rf.predict_proba(features_scaled)[0][1]
        svm_pred = self.model_svm.predict_proba(features_scaled)[0][1]
        nn_pred = self.model_nn.predict(features_scaled)[0][0]
        
        # Weighted ensemble
        avg_pred = (0.4 * rf_pred + 0.3 * svm_pred + 0.3 * nn_pred)
        
        # Risk level categorization
        risk_level = "Low"
        if avg_pred > 0.75:
            risk_level = "High"
        elif avg_pred > 0.5:
            risk_level = "Medium"
        
        return {
            'url': url,
            'random_forest': rf_pred,
            'svm': svm_pred,
            'neural_network': nn_pred,
            'average': avg_pred,
            'is_phishing': avg_pred > 0.5,
            'risk_level': risk_level,
            'features': features
        }