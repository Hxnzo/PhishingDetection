import requests 
import urllib3
import pandas as pd
import numpy as np
import re
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
        Scrape the website content from a given URL
        """
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, verify=False, timeout=10)
            html_content = response.text
            return html_content
        except Exception as e:
            print(f"Error scraping {url}: {str(e)}")
            return None
    
    def extract_features(self, url, html_content=None):
        """
        Extract features from URL and HTML content
        """
        # Normalize trailing slash so "https://google.com/" == "https://google.com"
        url = url.rstrip('/')

        features = {}
        
        # URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['has_https'] = 1 if url.startswith('https://') else 0
        
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
            return features
            
        # Parse HTML content
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # HTML features
        features['num_iframes'] = len(soup.find_all('iframe'))
        features['num_scripts'] = len(soup.find_all('script'))
        features['num_links'] = len(soup.find_all('a'))
        
        # Count suspicious HTML tags (often used in phishing)
        suspicious_tags = ['form', 'input', 'button', 'select', 'textarea']
        features['num_suspicious_tags'] = sum(len(soup.find_all(tag)) for tag in suspicious_tags)
        
        # Forms and password fields
        features['num_forms'] = len(soup.find_all('form'))
        features['has_password_field'] = 1 if soup.find('input', {'type': 'password'}) else 0
        
        # Images
        features['num_images'] = len(soup.find_all('img'))
        
        # External redirects in links
        external_redirects = 0
        domain = re.findall(r'://([^/]+)/?', url)
        domain = domain[0] if domain else ""
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http') and domain not in href:
                external_redirects += 1
        
        features['external_redirects'] = external_redirects
        
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
                # Optionally remove trailing slash from CSV data as well
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
                # Optionally remove trailing slash
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
    
    def train_models(self, dataset, test_size=0.2, random_state=42):
        """
        Train the machine learning models on the dataset and generate visualizations.
        """
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
        
        # Save feature names for later use
        self.features = X.columns.tolist()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state
        )
        
        # Scale data
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        print("Training Random Forest model...")
        self.model_rf = RandomForestClassifier(n_estimators=100, random_state=random_state, n_jobs=-1)
        self.model_rf.fit(X_train_scaled, y_train)
        rf_pred = self.model_rf.predict(X_test_scaled)
        rf_accuracy = accuracy_score(y_test, rf_pred)
        print(f"Random Forest accuracy: {rf_accuracy:.4f}")
        
        # Train SVM
        print("Training SVM model...")
        self.model_svm = SVC(probability=True, random_state=random_state)
        self.model_svm.fit(X_train_scaled, y_train)
        svm_pred = self.model_svm.predict(X_test_scaled)
        svm_accuracy = accuracy_score(y_test, svm_pred)
        print(f"SVM accuracy: {svm_accuracy:.4f}")
        
        # Train Neural Network with Early Stopping
        print("Training Neural Network model...")
        self.model_nn = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu', input_shape=(X_train_scaled.shape[1],)),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        self.model_nn.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        early_stop = tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=3)
        self.model_nn.fit(
            X_train_scaled, y_train,
            epochs=20,
            batch_size=32,
            verbose=0,
            validation_split=0.1,
            callbacks=[early_stop]
        )
        
        nn_pred = (self.model_nn.predict(X_test_scaled) > 0.5).astype(int).flatten()
        nn_accuracy = accuracy_score(y_test, nn_pred)
        print(f"Neural Network accuracy: {nn_accuracy:.4f}")
        
        # Visualize dataset with PCA (3D plot)
        pca = PCA(n_components=3)
        X_pca = pca.fit_transform(X)
        
        fig = plt.figure(figsize=(10, 8))
        ax = fig.add_subplot(111, projection='3d')
        
        legitimate = X_pca[y == 0]
        phishing = X_pca[y == 1]
        
        ax.scatter(legitimate[:, 0], legitimate[:, 1], legitimate[:, 2], c='blue', label='Legitimate')
        ax.scatter(phishing[:, 0], phishing[:, 1], phishing[:, 2], c='red', label='Phishing')
        
        ax.set_title('3D PCA of Website Features')
        ax.set_xlabel('PC1')
        ax.set_ylabel('PC2')
        ax.set_zlabel('PC3')
        ax.legend()
        
        plt.savefig('pca_visualization.png')
        plt.close()
        print("PCA visualization saved to pca_visualization.png")
        
        # --- Additional Visualizations ---

        # 1. Confusion Matrix for Ensemble Prediction
        rf_proba = self.model_rf.predict_proba(X_test_scaled)[:, 1]
        svm_proba = self.model_svm.predict_proba(X_test_scaled)[:, 1]
        nn_proba = self.model_nn.predict(X_test_scaled).flatten()
        ensemble_avg = (rf_proba + svm_proba + nn_proba) / 3
        ensemble_pred = (ensemble_avg > 0.5).astype(int)
        cm = confusion_matrix(y_test, ensemble_pred)
        plt.figure(figsize=(6, 5))
        plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
        plt.title('Confusion Matrix (Ensemble)')
        plt.colorbar()
        tick_marks = np.arange(2)
        plt.xticks(tick_marks, ['Legitimate', 'Phishing'], rotation=45)
        plt.yticks(tick_marks, ['Legitimate', 'Phishing'])
        thresh = cm.max() / 2.
        for i, j in np.ndindex(cm.shape):
            plt.text(j, i, format(cm[i, j], 'd'),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > thresh else "black")
        plt.ylabel('True label')
        plt.xlabel('Predicted label')
        plt.tight_layout()
        plt.savefig('confusion_matrix.png')
        plt.close()
        print("Confusion matrix saved to confusion_matrix.png")
        
        # 2. Feature Importance from Random Forest
        importances = self.model_rf.feature_importances_
        indices = np.argsort(importances)[::-1]
        plt.figure(figsize=(10, 6))
        plt.title("Feature Importances (Random Forest)")
        plt.bar(range(len(importances)), importances[indices], align="center")
        plt.xticks(range(len(importances)), [self.features[i] for i in indices], rotation=45)
        plt.ylabel("Importance")
        plt.tight_layout()
        plt.savefig('feature_importance.png')
        plt.close()
        print("Feature importance plot saved to feature_importance.png")
        
        # 3. Feature Correlation Heatmap
        plt.figure(figsize=(10, 8))
        correlation_matrix = dataset.drop('is_phishing', axis=1).corr()
        plt.imshow(correlation_matrix, interpolation='nearest', cmap=plt.cm.RdBu)
        plt.title("Feature Correlation")
        plt.colorbar()
        ticks = np.arange(len(correlation_matrix.columns))
        plt.xticks(ticks, correlation_matrix.columns, rotation=90)
        plt.yticks(ticks, correlation_matrix.columns)
        plt.tight_layout()
        plt.savefig('feature_correlation.png')
        plt.close()
        print("Feature correlation plot saved to feature_correlation.png")
        
        return {
            'RandomForest': rf_accuracy,
            'SVM': svm_accuracy,
            'NeuralNetwork': nn_accuracy
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
        # Normalize trailing slash here too (just in case user input includes a slash)
        url = url.rstrip('/')

        html_content = self.scrape_website(url)
        features = self.extract_features(url, html_content)
        
        features_df = pd.DataFrame([features])
        
        for feature in self.features:
            if feature not in features_df.columns:
                features_df[feature] = 0
        
        features_df = features_df[self.features]
        features_scaled = self.scaler.transform(features_df)
        
        rf_pred = self.model_rf.predict_proba(features_scaled)[0][1]
        svm_pred = self.model_svm.predict_proba(features_scaled)[0][1]
        nn_pred = self.model_nn.predict(features_scaled)[0][0]
        
        avg_pred = (rf_pred + svm_pred + nn_pred) / 3
        
        return {
            'url': url,
            'random_forest': rf_pred,
            'svm': svm_pred,
            'neural_network': nn_pred,
            'average': avg_pred,
            'is_phishing': avg_pred > 0.5,
            'features': features
        }

# ------------------------------------ WORKING CODE ABOVE -----------------------------------------------