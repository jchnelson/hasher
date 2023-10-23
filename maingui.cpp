#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QTextEdit>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QVBoxLayout>
#include <QString>
#include <string>

#include "hasher.h"

std::string textUpdate(const std::string& message, int algo_index)
{
    static int last = 50;
    static HashAlgo* current = 0;
    
    if (last != algo_index)
    {
        delete current;
        last = algo_index;
        switch (algo_index)
        {
        case 0:
            current = new MD5();
            break;
        case 1:
            current = new SHA1();
            break;
        case 2:
            current = new SHA256();
            break;
        case 3:
            current = new SHA512();
            break;
        case 4:
            current = new SHA224();
            break;
        case 5:
            current = new SHA384();
            break;
        case 6:
            current = new SHA512_224();
            break;
        case 7:
            current = new SHA512_256();
            break;
        }
    }
    return current->hash_string(message);
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QMainWindow w;
    QWidget* bigboss = new QWidget(&w);
    w.setCentralWidget(bigboss);
    
    QVBoxLayout* vlayout = new QVBoxLayout(bigboss);
    QTextEdit* mainbox = new QTextEdit(bigboss);
    QComboBox* algochooser = new QComboBox(bigboss);
    algochooser->addItems(QStringList() << "MD5" << "SHA-1"
                                        << "SHA-256" << "SHA-512"
                                        << "SHA-224" << "SHA-384"
                                        << "SHA-512/224" << "SHA-512/256");
    algochooser->setEditable(false);
    QLabel* outputlab = new QLabel(bigboss);
    
    vlayout->addWidget(mainbox);
    vlayout->addWidget(algochooser);
    vlayout->addWidget(outputlab);
    
    QObject::connect(mainbox, &QTextEdit::textChanged, [=] () {
        std::string bob = textUpdate(mainbox->toPlainText().toStdString(),
                                     algochooser->currentIndex());
        outputlab->setText(QString::fromStdString(bob));
    } );
    
    QObject::connect(algochooser, &QComboBox::currentIndexChanged, [=] () {
        std::string bob = textUpdate(mainbox->toPlainText().toStdString(),
                                     algochooser->currentIndex());
        outputlab->setText(QString::fromStdString(bob));
    } );
    
    w.show();
    return a.exec();
}
