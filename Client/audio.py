import pyttsx3

class TextToSpeech:
    def __init__(self):
        self.engine = pyttsx3.init()
        self.voice_enabled = False

    def speak(self, text):
        if self.voice_enabled:
            self.engine.say(text)
            self.engine.runAndWait()

    def set_voice_enabled(self, enabled):
        self.voice_enabled = enabled

    def is_enabled(self):
        return self.voice_enabled

# Exemple de test bref la juste un exemple statique
# if __name__ == "__main__":
#     tts = TextToSpeech()
#     tts.speak("Bienvenue dans secure sphere")
