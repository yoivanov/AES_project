using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
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

        public StepWIndow(int index)
        {
            InitializeComponent();

            BeforeSubBytes.ItemsSource = App.GetBeforeSubBytes(index);
            AfterSubBytes.ItemsSource = App.GetAfterSubBytes(index);

            MatrixModel[] beforeShiftRows = App.GetBeforeShiftRows(index);

            Cell00.DataContext = beforeShiftRows[0];
            Cell01.DataContext = beforeShiftRows[0];
            Cell02.DataContext = beforeShiftRows[0];
            Cell03.DataContext = beforeShiftRows[0];

            Cell10.DataContext = beforeShiftRows[1];
            Cell11.DataContext = beforeShiftRows[1];
            Cell12.DataContext = beforeShiftRows[1];
            Cell13.DataContext = beforeShiftRows[1];
            Cell14.DataContext = beforeShiftRows[1];

            Cell20.DataContext = beforeShiftRows[2];
            Cell21.DataContext = beforeShiftRows[2];
            Cell22.DataContext = beforeShiftRows[2];
            Cell23.DataContext = beforeShiftRows[2];
            Cell24.DataContext = beforeShiftRows[2];
            Cell25.DataContext = beforeShiftRows[2];

            Cell30.DataContext = beforeShiftRows[3];
            Cell31.DataContext = beforeShiftRows[3];
            Cell32.DataContext = beforeShiftRows[3];
            Cell33.DataContext = beforeShiftRows[3];
            Cell34.DataContext = beforeShiftRows[3];
            Cell35.DataContext = beforeShiftRows[3];
            Cell36.DataContext = beforeShiftRows[3];

            MatrixModel[] afterShiftRows = App.GetAfterShiftRows(index);

            BeforeMixColumns.ItemsSource = App.GetBeforeMixColumns(index);
            AfterMixColumns.ItemsSource = App.GetAfterMixColumns(index);

            BeforeRoundKey.ItemsSource = App.GetBeforeRoundKey(index);
            AfterRoundKey.ItemsSource = App.GetAfterRoundKey(index);

        }

        private void SBoxButton_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(App.ShowSbox());
        }


    }
}
