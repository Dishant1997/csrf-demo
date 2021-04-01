-- MySQL dump 10.13  Distrib 5.7.9, for osx10.9 (x86_64)
--
-- Host: 127.0.0.1    Database: CSRF
-- ------------------------------------------------------
-- Server version	5.7.10

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `Account`
--

DROP TABLE IF EXISTS `Account`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Account` (
  `idAccount` int(11) NOT NULL AUTO_INCREMENT,
  `firstName` varchar(45) NOT NULL,
  `lastName` varchar(45) NOT NULL,
  `email` varchar(45) NOT NULL,
  `password` varchar(100) NOT NULL,
  `money` decimal(10,2) NOT NULL DEFAULT '0.00',
  PRIMARY KEY (`idAccount`),
  UNIQUE KEY `idAccount_UNIQUE` (`idAccount`),
  UNIQUE KEY `email_UNIQUE` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Account`
--

LOCK TABLES `Account` WRITE;
/*!40000 ALTER TABLE `Account` DISABLE KEYS */;
INSERT INTO `Account` VALUES (17,'asdf','asdf','fff@asdf.com','$2a$10$Nc8KHGHJMpqXTaRo5rCi3OyFcK/fYgxxi2opyFsW4XuFp/FOHad8y',0.00),(22,'asdf','asdf','asdfas1df@asdf.com','$2a$10$dqywXsHPg7O/gka/rxZrdObhb2TWkq8knLLYJfbF7HwjYo9MHW7ZO',0.00),(23,'asdf','asdf','asdf1@asdf.com','$2a$10$Wj6nVqa0QFk8wWVSv5kbW.LVeowZX.mtuW4oUwhoTUgeQ.HtQDLfG',0.00),(24,'asdf','asdf','asdf2@asdf.com','$2a$10$XyJfjt7fmcY7zAjvIQoIvOFQqpIrV8IZrwLMjRgaWXkqKredvDaPC',0.00),(25,'asdf','asdf','ff@asdf.copm','$2a$10$faknxs30UX7fXeimfB/hnu/ksc2GWzqpL9CkGwmt46E80OEh2tbym',0.00),(26,'asdf','asdf','asdf22@asdf.com','$2a$10$tx3iyhe0ekZBI7R23WqKc.lCn3LnOPRsDjkqDzcLE0Bfdprc.HO.C',0.00),(27,'asdf','asdf','qwer@asdf.com','$2a$10$ceg7Vf7FYIzHftrlf.fL/O4NO.qD.dU/jExB/RJAE2BO65SgD3j9y',0.00),(28,'asdf','asdf','asdf23@asdfl.com','$2a$10$wMEyKD7rGr9xZ.Zir457IujX8H1baSnTcDEzJ4OBQJJUUrXjWiX6S',0.00),(29,'asdf','asdf','asdf@asdf.com','$2a$10$3Q23Q4ly2vuYRrb01IzlmOMRx6N2FNSqgjcRIgcWJdAAvJbsC.pm.',118.00),(30,'asdf','asdf','fdsa@asdf.com','$2a$10$vOiD3EyUbRLC3sgHuOdT6O/wcr980ER3MYqh5/hIoxVZielVB/cMi',0.00),(31,'asdf','asdf','email@asdf.com','$2a$10$KwROvJYGSeh0ZG5zh3Ot5.k8PyQSfCvZiWnGAJAuXLjP3l5Q7rboq',52.25),(32,'hacker','person','hacker@email.com','$2a$10$H3dKDW7vpbNMh76BDNfrEeugMoKW1cCw9Hxqr2iVuVm247Rg2WwOe',20.00);
/*!40000 ALTER TABLE `Account` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `Transaction`
--

DROP TABLE IF EXISTS `Transaction`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `Transaction` (
  `idTransaction` int(11) NOT NULL AUTO_INCREMENT,
  `toAccount` varchar(45) NOT NULL,
  `fromAccount` varchar(45) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  PRIMARY KEY (`idTransaction`),
  UNIQUE KEY `idTransaction_UNIQUE` (`idTransaction`),
  KEY `fromAccFK_idx` (`toAccount`,`fromAccount`)
) ENGINE=InnoDB AUTO_INCREMENT=29 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `Transaction`
--

LOCK TABLES `Transaction` WRITE;
/*!40000 ALTER TABLE `Transaction` DISABLE KEYS */;
INSERT INTO `Transaction` VALUES (1,'asdf@asdf.com','email@asdf.com',100.00),(2,'email@asdf.com','asdf@asdf.com',101.00),(3,'email@asdf.com','asdf@asdf.com',10.00),(4,'email@asdf.com','asdf@asdf.com',10.00),(5,'email@asdf.com','asdf@asdf.com',10.00),(6,'email@asdf.com','asdf@asdf.com',10.00),(7,'email@asdf.com','asdf@asdf.com',10.00),(8,'email@asdf.com','asdf@asdf.com',10.00),(9,'email@asdf.com','asdf@asdf.com',10.00),(10,'email@asdf.com','asdf@asdf.com',10.00),(11,'email@asdf.com','asdf@asdf.com',10.00),(12,'hacker@email.com','asdf@asdf.com',10.00),(13,'hacker@email.com','asdf@asdf.com',10.00),(14,'hacker@email.com','asdf@asdf.com',10.00),(15,'hacker@email.com','asdf@asdf.com',10.00),(16,'asdf@asdf.com','hacker@email.com',20.00),(17,'email@asdf.com','asdf@asdf.com',5.00),(18,'asdf@asdf.com','email@asdf.com',100.00),(19,'asdf@asdf.com','email@asdf.com',5.50),(20,'asdf@asdf.com','email@asdf.com',5.50),(21,'asdf@asdf.com','email@asdf.com',5.50),(22,'asdf@asdf.com','email@asdf.com',10.00),(23,'asdf@asdf.com','email@asdf.com',8.50),(24,'email@asdf.com','asdf@asdf.com',10.20),(25,'email@asdf.com','asdf@asdf.com',0.30),(26,'email@asdf.com','asdf@asdf.com',0.30),(27,'email@asdf.com','asdf@asdf.com',10.75),(28,'email@asdf.com','asdf@asdf.com',0.70);
/*!40000 ALTER TABLE `Transaction` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2016-05-31 23:15:55
