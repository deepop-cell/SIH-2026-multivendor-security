from reportlab.pdfgen import canvas
c = canvas.Canvas("Final_Audit.pdf")
c.drawString(100, 750, "Vulnerability Found. Copy this code to fix: crypto key generate rsa")
c.save()