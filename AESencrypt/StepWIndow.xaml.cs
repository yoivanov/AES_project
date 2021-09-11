using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace AESencrypt
{
    /// <summary>
    /// Interaction logic for StepWIndow.xaml
    /// </summary>
    public partial class StepWIndow : Window
    {
        public ObservableCollection<byte> data = new ObservableCollection<byte>();

        public StepWIndow()
        {
            InitializeComponent();
            data = App.ShowStep();
            MixColDataGrid.ItemsSource = data;
        }

        private void sBoxButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowSbox());
        }

        private void ShowSbox()
        {

            Button sBoxButton = new Button
            {
                Content = "sBox"
            };
            sBoxButton.Click += sBoxButton_Click;

        }
    }
}
