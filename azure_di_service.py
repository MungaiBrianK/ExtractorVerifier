from azure.ai.formrecognizer import DocumentAnalysisClient
from azure.core.credentials import AzureKeyCredential
from config import AZURE_DI_ENDPOINT, AZURE_DI_API_KEY # Import configuration

class AzureDocumentIntelligenceService:
    def __init__(self, endpoint, api_key, custom_model_id=None):
        """
        Initializes the Azure Document Intelligence client.
        """
        if not endpoint or not api_key:
            raise ValueError("Azure Document Intelligence endpoint and API key must be provided.")

        self.document_analysis_client = DocumentAnalysisClient(
            endpoint=endpoint,
            credential=AzureKeyCredential(api_key)
        )
        self.custom_model_id = custom_model_id
        print(f"INFO: Azure Document Intelligence Client initialized for endpoint: {endpoint}")
        if custom_model_id:
            print(f"INFO: Custom model ID set to: {custom_model_id}")

    def _process_document_result(self, result, model_used):
        """
        Helper method to process the result from Azure Document Intelligence,
        extracting specific fields and confidence scores.
        """
        extracted_data = {}
        confidence_info = {}

        print(f"🔍 Debug: Analyzing response structure from Azure Document Intelligence using {model_used}...")

        field_mappings = {
            'FULLNAMES': 'Full Names',
            'IDNUMBER': 'ID Number',
            'SERIALNUMBER': 'Serial Number',
            'DATEOFBIRTH': 'Date of Birth',
        }

        if result.documents:
            print(f"📄 Found {len(result.documents)} document(s)")
            for i, document in enumerate(result.documents):
                print(f"📋 Document {i+1}:")
                print(f"--- Raw Document {i+1} Structure (from {model_used}) ---")
                print(f"Document Type: {document.doc_type}")

                if hasattr(document, 'fields') and document.fields:
                    fields_from_api = document.fields
                    print(f"   Found {len(fields_from_api)} fields from API response.")

                    for field_key, display_name in field_mappings.items():
                        field_value = "N/A" # Default to N/A if not found or empty
                        if field_key in fields_from_api:
                            field_obj = fields_from_api[field_key]
                            temp_value = None
                            try:
                                if hasattr(field_obj, 'value') and field_obj.value is not None:
                                    if hasattr(field_obj.value, 'strftime'):
                                        temp_value = field_obj.value.strftime("%Y-%m-%d")
                                    else:
                                        temp_value = field_obj.value
                                elif hasattr(field_obj, 'content') and field_obj.content is not None:
                                    temp_value = field_obj.content
                                elif hasattr(field_obj, 'value_string') and field_obj.value_string is not None:
                                    temp_value = field_obj.value_string

                                if temp_value is not None and str(temp_value).strip() != '':
                                    field_value = str(temp_value).strip()
                                else:
                                    field_value = "Not Found / Empty"
                            except Exception as field_error:
                                print(f"   ❌ Error processing field {field_key}: {field_error}")
                                field_value = "Error Processing"

                        extracted_data[display_name] = field_value
                        print(f"   Raw Extracted: {field_key} -> Value: {field_value}, Confidence: {field_obj.confidence if field_key in fields_from_api and hasattr(fields_from_api[field_key], 'confidence') else 'N/A'}")
                else:
                    print("   No fields found in this document via structured extraction.")
                print("------------------------------------")

                try:
                    if hasattr(document, 'confidence') and document.confidence is not None:
                        confidence_info['Overall Confidence'] = f"{document.confidence * 100:.1f}%"
                    if hasattr(document, 'doc_type_confidence') and document.doc_type_confidence is not None:
                        confidence_info['Document Type Confidence'] = f"{document.doc_type_confidence * 100:.1f}%"
                except Exception as conf_error:
                    print(f"⚠️ Could not extract confidence: {conf_error}")

        if not extracted_data and hasattr(result, 'key_value_pairs') and result.key_value_pairs:
            print("🔑 Trying key-value pairs extraction (fallback)...")
            for kv_pair in result.key_value_pairs:
                if kv_pair.key and kv_pair.value:
                    key_text = kv_pair.key.content if hasattr(kv_pair.key, 'content') else str(kv_pair.key)
                    value_text = kv_pair.value.content if hasattr(kv_pair.value, 'content') else str(kv_pair.value)
                    if key_text and value_text and key_text.strip() != '' and value_text.strip() != '':
                        extracted_data[key_text.strip()] = value_text.strip()
                        print(f"   Extracted (KV Pair): {key_text.strip()} = {value_text.strip()}")

        print(f"📊 Final extracted data items to display: {len(extracted_data)}")
        extracted_data['Model Used'] = model_used

        return {
            'data': extracted_data,
            'confidence': confidence_info
        }

    def analyze_document_with_custom_model(self, document_bytes):
        """
        Analyzes a document using the specified custom model.
        Returns the raw analysis result object.
        """
        if not self.custom_model_id:
            raise ValueError("Custom model ID is not set for AzureDocumentIntelligenceService.")
        if not self.document_analysis_client:
            raise RuntimeError("Azure Document Intelligence client is not initialized.")

        print(f"Attempting analysis with CUSTOM MODEL: {self.custom_model_id}")
        poller = self.document_analysis_client.begin_analyze_document(self.custom_model_id, document_bytes)
        result = poller.result()
        return self._process_document_result(result, self.custom_model_id)

    def analyze_id_document(self, document_bytes):
        """
        Analyzes an ID document using the prebuilt 'prebuilt-idDocument' model.
        Returns the raw analysis result object.
        """
        if not self.document_analysis_client:
            raise RuntimeError("Azure Document Intelligence client is not initialized.")

        print("Attempting analysis with PREBUILT ID DOCUMENT MODEL")
        poller = self.document_analysis_client.begin_analyze_document("prebuilt-idDocument", document_bytes)
        result = poller.result()
        return self._process_document_result(result, "prebuilt-idDocument")

