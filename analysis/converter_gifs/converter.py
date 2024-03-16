from moviepy.editor import VideoFileClip

def convert_webm_to_gif(input_path, output_path, fps=100):
    try:
        # Carrega o vídeo WebM
        video_clip = VideoFileClip(input_path)
        
        # Define a taxa de quadros para a animação GIF
        video_clip = video_clip.set_fps(fps)
        
        # Salva o vídeo como GIF
        video_clip.write_gif(output_path, fps=fps)
        
        print(f"Conversão concluída. GIF salvo em: {output_path}")
        
    except Exception as e:
        print(f"Ocorreu um erro durante a conversão: {e}")

# Exemplo de uso
input_webm_path = "../videos/oldpass.webm"
output_gif_path = "../img/oldpass.gif"

convert_webm_to_gif(input_webm_path, output_gif_path, fps=100)
