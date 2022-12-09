import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class ImageCryptography {

	// Function to encrypt and decrypt the image 
    public static void operate(int key) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.showOpenDialog(null);
        File file = fileChooser.getSelectedFile();
        try {
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[fis.available()];
            fis.read(data);
            int i = 0;
            for (byte b : data) {
                data[i] = (byte) (b ^ key);
                i++;
            }

            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data);
            fos.close();
            fis.close();
            JOptionPane.showMessageDialog(null, "SUCCESS");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Main Method
    public static void main(String[] args) {

        JFrame f = new JFrame();
        f.setTitle("Image Encryption");
        f.setSize(500, 500);
        f.setLocationRelativeTo(null);
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // font set
        Font font = new Font("Roboto", Font.BOLD, 25);

        //creating text field
        JTextField textField = new JTextField(10);
        textField.setFont(font);

        // creating button
        JButton button = new JButton();
        button.setText("Encrypt");
        button.setFont(font);
        JButton button1 = new JButton();
        button1.setText("Decrypt");
        button1.setFont(font);

        button.addActionListener(e -> {
            System.out.println("button clicks");
            try {
                String text = textField.getText();
                int temp = Integer.parseInt(text);
                operate(temp);
            } catch (Exception ex) {
            	JOptionPane.showMessageDialog(null,"Enter a number");
            }
        });

        button1.addActionListener(e -> {
            System.out.println("button clicks");
            try {
                String text = textField.getText();
                int temp = Integer.parseInt(text);
                operate(temp);
            } catch (Exception ex) {
            	JOptionPane.showMessageDialog(null,"Enter a number");
            }
        });
        
        f.setLayout(new FlowLayout());
        f.add(textField);
        f.add(button);
        f.add(button1);
        f.setVisible(true);
    }
}