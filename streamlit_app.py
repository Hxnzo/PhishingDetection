import streamlit as st
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from phishing_detector import PhishingDetector

def load_detector():
    @st.cache_resource
    def _load_detector():
        detector = PhishingDetector()
        required_files = [
            "models/model_rf.pkl",
            "models/model_svm.pkl",
            "models/model_nn.keras",
            "models/scaler.pkl",
            "models/features.pkl"
        ]
        if all(os.path.exists(file) for file in required_files):
            detector.load_models()
            return detector, True
        else:
            return detector, False

    detector, models_loaded = _load_detector()
    if not models_loaded:
        st.warning("Models not found. Please train the models first using the 'Train Models' tab.")
    return detector, models_loaded

def main():
    st.set_page_config(page_title="Phishing Detection System", page_icon="🛡️", layout="wide")
    
    st.title("🛡️ Advanced Phishing Detection System")
    st.markdown("""
    This application uses machine learning to detect phishing websites with high accuracy. 
    It employs a weighted ensemble of Random Forest, Support Vector Machine, and Neural Network models.
    """)
    
    detector, models_loaded = load_detector()
    
    # Create three tabs
    tab1, tab2, tab3 = st.tabs(["Check URL", "Train Models", "About"])
    
    # ---------------
    # TAB 1: Check URL
    # ---------------
    with tab1:
        st.header("Check if a URL is a phishing website")
        
        # Input box and button in a single column
        url = st.text_input("Enter a URL to check:", "https://example.com")
        
        if st.button("Check URL", use_container_width=True):
            if not models_loaded:
                st.error("Please train the models first using the 'Train Models' tab.")
            else:
                with st.spinner("Analyzing the URL..."):
                    try:
                        # Get the detection results
                        result = detector.check_url(url)
                        
                        # Display overall risk info
                        st.subheader("Phishing Detection Results")
                        risk_color = "green"
                        if result['risk_level'] == "Medium":
                            risk_color = "orange"
                        elif result['risk_level'] == "High":
                            risk_color = "red"
                        
                        st.markdown(f"""
                        <div style="text-align: center;">
                            <h3 style="color: {risk_color};">Risk Level: {result['risk_level']}</h3>
                            <h4>Confidence: {result['average']*100:.1f}%</h4>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Simple success/error message
                        if result['is_phishing']:
                            st.error("⚠️ The URL is likely a phishing website!")
                        else:
                            st.success("✅ The URL appears to be legitimate.")
                        
                        # Show model predictions in a horizontal bar chart
                        st.subheader("Model Predictions")
                        data = {
                            'Model': ['Random Forest', 'SVM', 'Neural Network', 'Ensemble'],
                            'Score': [
                                result['random_forest'],
                                result['svm'],
                                result['neural_network'],
                                result['average']
                            ]
                        }
                        chart_df = pd.DataFrame(data)
                        
                        fig, ax = plt.subplots(figsize=(6, 3))
                        colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728']
                        ax.barh(chart_df['Model'], chart_df['Score'], color=colors)
                        ax.set_xlim(0, 1)
                        ax.set_xlabel('Phishing Score')
                        ax.axvline(x=0.5, color='red', linestyle='--', alpha=0.5)
                        plt.tight_layout()
                        st.pyplot(fig)
                        
                        # Show key features in a small table
                        st.subheader("Key Features")
                        key_features = {
                            'URL Length': result['features'].get('url_length', 'N/A'),
                            'Has HTTPS': 'Yes' if result['features'].get('has_https', 0) == 1 else 'No',
                            'Password Field': 'Yes' if result['features'].get('has_password_field', 0) == 1 else 'No',
                            'External Redirects': result['features'].get('external_redirects', 'N/A'),
                            'Suspicious Tags': result['features'].get('num_suspicious_tags', 'N/A'),
                            'Popup Elements': result['features'].get('popup_count', 'N/A'),
                            'Hidden Elements': result['features'].get('invisible_elements', 'N/A'),
                            'Scripts': result['features'].get('num_scripts', 'N/A')
                        }
                        key_features_df = pd.DataFrame(list(key_features.items()), columns=['Feature', 'Value'])
                        # Convert all values to strings to ensure consistent column type
                        key_features_df['Value'] = key_features_df['Value'].astype(str)
                        st.table(key_features_df)
                        
                        # Optionally allow user to expand and see all features
                        with st.expander("View All Features"):
                            st.json(result['features'])
                    
                    except Exception as e:
                        st.error(f"Error checking URL: {str(e)}")

    # ---------------
    # TAB 2: Train Models
    # ---------------
    with tab2:
        st.header("Train Phishing Detection Models")
        st.markdown("""
        Upload CSV files containing lists of URLs to train the detection models.
        
        **Requirements:**
        - CSV files should not have headers
        - Each row should contain one URL
        - Include both legitimate and phishing URLs for best results
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            legitimate_file = st.file_uploader("Upload Legitimate URLs CSV", type=["csv"], key="legit")
            if legitimate_file is not None:
                legitimate_preview = pd.read_csv(legitimate_file, header=None)
                st.write(f"Legitimate URLs sample ({len(legitimate_preview)} total):")
                st.dataframe(legitimate_preview.head(5))
        
        with col2:
            phishing_file = st.file_uploader("Upload Phishing URLs CSV", type=["csv"], key="phish")
            if phishing_file is not None:
                phishing_preview = pd.read_csv(phishing_file, header=None)
                st.write(f"Phishing URLs sample ({len(phishing_preview)} total):")
                st.dataframe(phishing_preview.head(5))
        
        if st.button("Train Models", use_container_width=True):
            if legitimate_file is None or phishing_file is None:
                st.error("Please upload both legitimate and phishing URL files.")
            else:
                with st.spinner("Training models. This may take several minutes..."):
                    try:
                        # Reset file pointers
                        legitimate_file.seek(0)
                        phishing_file.seek(0)
                        
                        legitimate_urls = pd.read_csv(legitimate_file, header=None)[0].tolist()
                        phishing_urls = pd.read_csv(phishing_file, header=None)[0].tolist()

                        test_size = 0.2
                        rf_estimators = 200
                        svm_kernel = "rbf"
                        nn_epochs = 50
                        
                        # Train the models
                        training_results = detector.train_models(
                            legitimate_urls, 
                            phishing_urls, 
                            test_size=test_size,
                            rf_estimators=rf_estimators,
                            svm_kernel=svm_kernel,
                            nn_epochs=nn_epochs
                        )
                        
                        st.success("Models trained successfully!")
                        
                        st.subheader("Model Performance")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        col1.metric("Accuracy", f"{training_results['accuracy']*100:.1f}%")
                        col2.metric("Precision", f"{training_results['precision']*100:.1f}%")
                        col3.metric("Recall", f"{training_results['recall']*100:.1f}%")
                        col4.metric("F1 Score", f"{training_results['f1']*100:.1f}%")
                        
                        st.subheader("Confusion Matrix")
                        cm = training_results['confusion_matrix']
                        
                        fig, ax = plt.subplots(figsize=(6, 5))
                        im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
                        ax.figure.colorbar(im, ax=ax)
                        ax.set(xticks=[0, 1], yticks=[0, 1],
                               xticklabels=['Legitimate', 'Phishing'],
                               yticklabels=['Legitimate', 'Phishing'],
                               ylabel='True label',
                               xlabel='Predicted label')
                        
                        thresh = cm.max() / 2
                        for i in range(cm.shape[0]):
                            for j in range(cm.shape[1]):
                                ax.text(j, i, format(cm[i, j], 'd'),
                                        ha="center", va="center",
                                        color="white" if cm[i, j] > thresh else "black")
                        
                        plt.tight_layout()
                        st.pyplot(fig)
                        
                        if 'feature_importance' in training_results:
                            st.subheader("Feature Importance")
                            
                            feat_imp = training_results['feature_importance']
                            sorted_idx = np.argsort(feat_imp)
                            feature_names = training_results.get('feature_names', [f'Feature {i}' for i in range(len(feat_imp))])
                            
                            top_n = min(10, len(sorted_idx))
                            top_idx = sorted_idx[-top_n:]
                            
                            fig, ax = plt.subplots(figsize=(8, 6))
                            ax.barh(range(top_n), feat_imp[top_idx])
                            ax.set_yticks(range(top_n))
                            ax.set_yticklabels([feature_names[i] for i in top_idx])
                            ax.set_xlabel('Feature Importance')
                            plt.tight_layout()
                            st.pyplot(fig)
                        
                    except Exception as e:
                        st.error(f"Error training models: {str(e)}")
    
    # ---------------
    # TAB 3: About
    # ---------------
    with tab3:
        st.header("About This Application")
        st.markdown("""
        ### Phishing Detection System
        
        This application uses machine learning to identify potentially malicious phishing websites
        by analyzing various features extracted from URLs and their corresponding websites.
        
        #### How It Works
        
        1. **URL Analysis**: The system extracts features from the URL itself, such as length, 
           presence of suspicious characters, domain information, etc.
           
        2. **Content Analysis**: For accessible websites, the system analyzes the HTML content,
           looking for suspicious elements like hidden fields, external redirects, and more.
           
        3. **ML Models**: The system uses a weighted ensemble of multiple models:
           - Random Forest: Good at handling various feature types
           - Support Vector Machine: Effective at finding decision boundaries
           - Neural Network: Capable of learning complex patterns
           
        4. **Ensemble Decision**: The final verdict is determined by a weighted average of all models,
           providing more reliable results than any single model.
        
        #### Limitations
        
        - The system requires internet access to analyze website content
        - Some websites may block automated requests
        - The system works best when trained on recent phishing examples
        - False positives may occur for legitimate but unusual websites
        """)

if __name__ == "__main__":
    main()