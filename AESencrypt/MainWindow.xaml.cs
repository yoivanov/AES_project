using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace AESencrypt
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private AesLib.Aes.KeySize keySize;
        private int neededKeyLength;


        public MainWindow()
        {
            InitializeComponent();
        }






        private void use128bit_Checked(object sender, RoutedEventArgs e)
        {
            this.keySize = AesLib.Aes.KeySize.Bits128;
            this.neededKeyLength = 16;
        }

        private void use192bit_Checked(object sender, RoutedEventArgs e)
        {
            this.keySize = AesLib.Aes.KeySize.Bits192;
            this.neededKeyLength = 24;
        }

        private void use256bit_Checked(object sender, RoutedEventArgs e)
        {
            this.keySize = AesLib.Aes.KeySize.Bits256;
            this.neededKeyLength = 32;
        }




        private void EncryptBtn_Click(object sender, RoutedEventArgs e)
        {
            string text = this.textinputField.Text;
            string key = this.keyinputField.Text;

            if (!App.IsKeyCorrect(key, this.neededKeyLength))
            {
                this.outputField.Text =
                    $"The given key is not the needed size for the chosen option. The given key is {key.Length} bytes long, {this.neededKeyLength} bytes are needed.";
            }
            else
            {
                // the actual encryption
                this.outputField.Text = App.Encryption(text, key, this.keySize);

                // Prepare the steps to be shown
                GenerateStepButtonsEncrypt();
            }
        }

        private void GenerateStepButtonsEncrypt()
        {
            // In the future the buttons should be dynamically generated

            preStepsList.Children.Clear();
            aesStepsList.Children.Clear();

            Button keyScheduleButton = new Button
            {
                Content = "key schedule"
            };
            keyScheduleButton.Click += KeyScheduleButton_Click;
            preStepsList.Children.Add(keyScheduleButton);

            Button sBoxButton = new Button
            {
                Content = "sBox"
            };
            sBoxButton.Click += sBoxButton_Click;
            preStepsList.Children.Add(sBoxButton);

            Button roundConstantButton = new Button
            {
                Content = "round constants"
            };
            roundConstantButton.Click += roundConstantButton_Click;
            preStepsList.Children.Add(roundConstantButton);

            for (int i = 0; i < App.NumberOfRounds; i++)
            {
                Button roundsButton = new Button
                {
                    Content = $"Step {i + 1}"
                };
                roundsButton.Click += roundsButton_Click;
                aesStepsList.Children.Add(roundsButton);
            }

        }

        private void KeyScheduleButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowKeySchedule());
        }

        private void sBoxButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowSbox());
        }

        private void roundConstantButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowRcon());
        }

        private void roundsButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var roundIndex = int.Parse(button.Content.ToString().Split(' ')[1]);

            StepWIndow stepWindow = new StepWIndow();
            stepWindow.Show();
        }



        private void DecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            string text = this.textinputField.Text;
            string key = this.keyinputField.Text;

            if (!App.IsKeyCorrect(key, this.neededKeyLength))
            {
                this.outputField.Text =
                    $"The given key is not the needed size for the chosen option. The given key is {key.Length} bytes long, {this.neededKeyLength} bytes are needed.";
            }
            else if (!App.IsDecryptStringCorrect(text))
            {
                this.outputField.Text =
                    $"The given string to decrypt is not of correct length";
            }
            else
            {
                this.outputField.Text = App.Decryption(text, key, this.keySize);

                // Prepare the steps to be shown
                GenerateStepButtonsDecrypt();
            }
        }



        private void GenerateStepButtonsDecrypt()
        {
            // In the future the buttons should be dynamically generated

            preStepsList.Children.Clear();
            aesStepsList.Children.Clear();

            Button DkeyScheduleButton = new Button
            {
                Content = "key schedule"
            };
            DkeyScheduleButton.Click += DKeyScheduleButton_Click;
            preStepsList.Children.Add(DkeyScheduleButton);

            Button DsBoxButton = new Button
            {
                Content = "sBox"
            };
            DsBoxButton.Click += DsBoxButton_Click;
            preStepsList.Children.Add(DsBoxButton);

            Button DroundConstantButton = new Button
            {
                Content = "round constants"
            };
            DroundConstantButton.Click += DroundConstantButton_Click;
            preStepsList.Children.Add(DroundConstantButton);

            for (int i = 0; i < App.NumberOfRounds; i++)
            {
                Button roundsButton = new Button
                {
                    Content = $"Step {i + 1}"
                };
                roundsButton.Click += DroundsButton_Click;
                aesStepsList.Children.Add(roundsButton);
            }
        }

        private void DKeyScheduleButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowKeySchedule());
        }

        private void DsBoxButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowDSbox());
        }

        private void DroundConstantButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowRcon());
        }

        private void DroundsButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowDRounds());
        }
    }
}
