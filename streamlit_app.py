import streamlit as st
import os
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
        else:
            st.warning("Models not found. Please train the models first.")
        return detector
    return _load_detector()

def main():
    st.set_page_config(page_title="Phishing Detection System", page_icon="🛡️", layout="wide")
    
    st.title("🛡️ Phishing Detection System")
    st.markdown("""
    This application uses machine learning to detect phishing websites. 
    It employs a combination of Random Forest, Support Vector Machine, and Neural Network models.
    """)
    
    detector = load_detector()
    
    tab1, tab2, tab3 = st.tabs(["Check URL", "Train Models", "About"])
    
    with tab1:
        st.header("Check if a URL is a phishing website")
        url = st.text_input("Enter a URL to check:", "https://example.com")
        
        if st.button("Check URL"):
            with st.spinner("Analyzing the URL..."):
                try:
                    result = detector.check_url(url)
                    st.subheader("Results")
                    st.write(f"**Random Forest Prediction:** {result['random_forest']:.4f}")
                    st.write(f"**SVM Prediction:** {result['svm']:.4f}")
                    st.write(f"**Neural Network Prediction:** {result['neural_network']:.4f}")
                    st.write(f"**Average Prediction:** {result['average']:.4f}")
                    if result['is_phishing']:
                        st.error("The URL is likely a phishing website!")
                    else:
                        st.success("The URL appears to be legitimate.")
                    st.json(result['features'])
                except Exception as e:
                    st.error(f"Error checking URL: {str(e)}")
    
    with tab2:
        st.header("Train Phishing Detection Models")
        st.markdown("Upload CSV files containing lists of URLs. The CSV files should not have headers and should contain one URL per line.")
        
        legitimate_file = st.file_uploader("Upload Legitimate URLs CSV", type=["csv"], key="legit")
        phishing_file = st.file_uploader("Upload Phishing URLs CSV", type=["csv"], key="phish")
        
        if legitimate_file is not None and phishing_file is not None:
            if st.button("Train Models"):
                try:
                    for filename in ["legitimate_urls.csv", "phishing_urls.csv"]:
                        if os.path.exists(filename):
                            os.remove(filename)
                    
                    with open("legitimate_urls.csv", "wb") as f:
                        f.write(legitimate_file.getbuffer())
                    with open("phishing_urls.csv", "wb") as f:
                        f.write(phishing_file.getbuffer())
                    
                    dataset = detector.load_or_create_dataset("legitimate_urls.csv", "phishing_urls.csv")
                    
                    st.write("Class distribution in dataset:")
                    st.write(dataset['is_phishing'].value_counts())
                    
                    accuracies = detector.train_models(dataset)
                    detector.save_models()
                    
                    st.success("Models trained and saved successfully!")
                    st.write("### Model Accuracies")
                    st.write(f"**Random Forest:** {accuracies['RandomForest']:.4f}")
                    st.write(f"**SVM:** {accuracies['SVM']:.4f}")
                    st.write(f"**Neural Network:** {accuracies['NeuralNetwork']:.4f}")
                    
                    st.image("pca_visualization.png", caption="PCA Visualization")
                    st.image("confusion_matrix.png", caption="Confusion Matrix (Ensemble)")
                    st.image("feature_importance.png", caption="Feature Importance (Random Forest)")
                    st.image("feature_correlation.png", caption="Feature Correlation")
                except Exception as e:
                    st.error(f"Error during training: {str(e)}")
    
    with tab3:
        st.header("About")
        st.markdown("""
        This phishing detection system is designed to help identify malicious websites by analyzing both URL-based and HTML-based features.
        The system uses a combination of machine learning models:
        - **Random Forest**
        - **Support Vector Machine (SVM)**
        - **Neural Network**

        The application scrapes website content, extracts features, and then applies these models to determine the likelihood that a website is phishing.
        """)
    
if __name__ == '__main__':
    main()

# ------------------------------------ WORKING CODE ABOVE -----------------------------------------------