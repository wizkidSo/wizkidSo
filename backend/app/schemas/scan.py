from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str


URLScanRequest.model_rebuild()




class EmailScanRequest(BaseModel):
    email_text: str = Field(
        ...,
        min_length=1,
        max_length=20000,
        description="Email subject and body to analyze"
    )