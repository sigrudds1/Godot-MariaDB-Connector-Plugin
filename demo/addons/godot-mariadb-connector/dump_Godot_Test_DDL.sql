-- MariaDB dump 10.19  Distrib 10.10.7-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: Godot_Test
-- ------------------------------------------------------
-- Server version	10.10.7-MariaDB-1:10.10.7+maria~ubu2204

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `many_columns`
--

DROP TABLE IF EXISTS `many_columns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `many_columns` (
  `Column1` int(11) DEFAULT NULL,
  `Column2` int(11) DEFAULT NULL,
  `Column3` int(11) DEFAULT NULL,
  `Column4` int(11) DEFAULT NULL,
  `Column5` int(11) DEFAULT NULL,
  `Column6` int(11) DEFAULT NULL,
  `Column7` int(11) DEFAULT NULL,
  `Column8` int(11) DEFAULT NULL,
  `Column9` int(11) DEFAULT NULL,
  `Column10` int(11) DEFAULT NULL,
  `Column11` int(11) DEFAULT NULL,
  `Column12` int(11) DEFAULT NULL,
  `Column13` int(11) DEFAULT NULL,
  `Column14` int(11) DEFAULT NULL,
  `Column15` int(11) DEFAULT NULL,
  `Column16` int(11) DEFAULT NULL,
  `Column17` int(11) DEFAULT NULL,
  `Column18` int(11) DEFAULT NULL,
  `Column19` int(11) DEFAULT NULL,
  `Column20` int(11) DEFAULT NULL,
  `Column21` int(11) DEFAULT NULL,
  `Column22` int(11) DEFAULT NULL,
  `Column23` int(11) DEFAULT NULL,
  `Column24` int(11) DEFAULT NULL,
  `Column25` int(11) DEFAULT NULL,
  `Column26` int(11) DEFAULT NULL,
  `Column27` int(11) DEFAULT NULL,
  `Column28` int(11) DEFAULT NULL,
  `Column29` int(11) DEFAULT NULL,
  `Column30` int(11) DEFAULT NULL,
  `Column31` int(11) DEFAULT NULL,
  `Column32` int(11) DEFAULT NULL,
  `Column33` int(11) DEFAULT NULL,
  `Column34` int(11) DEFAULT NULL,
  `Column35` int(11) DEFAULT NULL,
  `Column36` int(11) DEFAULT NULL,
  `Column37` int(11) DEFAULT NULL,
  `Column38` int(11) DEFAULT NULL,
  `Column39` int(11) DEFAULT NULL,
  `Column40` int(11) DEFAULT NULL,
  `Column41` int(11) DEFAULT NULL,
  `Column42` int(11) DEFAULT NULL,
  `Column43` int(11) DEFAULT NULL,
  `Column44` int(11) DEFAULT NULL,
  `Column45` int(11) DEFAULT NULL,
  `Column46` int(11) DEFAULT NULL,
  `Column47` int(11) DEFAULT NULL,
  `Column48` int(11) DEFAULT NULL,
  `Column49` int(11) DEFAULT NULL,
  `Column50` int(11) DEFAULT NULL,
  `Column51` int(11) DEFAULT NULL,
  `Column52` int(11) DEFAULT NULL,
  `Column53` int(11) DEFAULT NULL,
  `Column54` int(11) DEFAULT NULL,
  `Column55` int(11) DEFAULT NULL,
  `Column56` int(11) DEFAULT NULL,
  `Column57` int(11) DEFAULT NULL,
  `Column58` int(11) DEFAULT NULL,
  `Column59` int(11) DEFAULT NULL,
  `Column60` int(11) DEFAULT NULL,
  `Column61` int(11) DEFAULT NULL,
  `Column62` int(11) DEFAULT NULL,
  `Column63` int(11) DEFAULT NULL,
  `Column64` int(11) DEFAULT NULL,
  `Column65` int(11) DEFAULT NULL,
  `Column66` int(11) DEFAULT NULL,
  `Column67` int(11) DEFAULT NULL,
  `Column68` int(11) DEFAULT NULL,
  `Column69` int(11) DEFAULT NULL,
  `Column70` int(11) DEFAULT NULL,
  `Column71` int(11) DEFAULT NULL,
  `Column72` int(11) DEFAULT NULL,
  `Column73` int(11) DEFAULT NULL,
  `Column74` int(11) DEFAULT NULL,
  `Column75` int(11) DEFAULT NULL,
  `Column76` int(11) DEFAULT NULL,
  `Column77` int(11) DEFAULT NULL,
  `Column78` int(11) DEFAULT NULL,
  `Column79` int(11) DEFAULT NULL,
  `Column80` int(11) DEFAULT NULL,
  `Column81` int(11) DEFAULT NULL,
  `Column82` int(11) DEFAULT NULL,
  `Column83` int(11) DEFAULT NULL,
  `Column84` int(11) DEFAULT NULL,
  `Column85` int(11) DEFAULT NULL,
  `Column86` int(11) DEFAULT NULL,
  `Column87` int(11) DEFAULT NULL,
  `Column88` int(11) DEFAULT NULL,
  `Column89` int(11) DEFAULT NULL,
  `Column90` int(11) DEFAULT NULL,
  `Column91` int(11) DEFAULT NULL,
  `Column92` int(11) DEFAULT NULL,
  `Column93` int(11) DEFAULT NULL,
  `Column94` int(11) DEFAULT NULL,
  `Column95` int(11) DEFAULT NULL,
  `Column96` int(11) DEFAULT NULL,
  `Column97` int(11) DEFAULT NULL,
  `Column98` int(11) DEFAULT NULL,
  `Column99` int(11) DEFAULT NULL,
  `Column100` int(11) DEFAULT NULL,
  `Column101` int(11) DEFAULT NULL,
  `Column102` int(11) DEFAULT NULL,
  `Column103` int(11) DEFAULT NULL,
  `Column104` int(11) DEFAULT NULL,
  `Column105` int(11) DEFAULT NULL,
  `Column106` int(11) DEFAULT NULL,
  `Column107` int(11) DEFAULT NULL,
  `Column108` int(11) DEFAULT NULL,
  `Column109` int(11) DEFAULT NULL,
  `Column110` int(11) DEFAULT NULL,
  `Column111` int(11) DEFAULT NULL,
  `Column112` int(11) DEFAULT NULL,
  `Column113` int(11) DEFAULT NULL,
  `Column114` int(11) DEFAULT NULL,
  `Column115` int(11) DEFAULT NULL,
  `Column116` int(11) DEFAULT NULL,
  `Column117` int(11) DEFAULT NULL,
  `Column118` int(11) DEFAULT NULL,
  `Column119` int(11) DEFAULT NULL,
  `Column120` int(11) DEFAULT NULL,
  `Column121` int(11) DEFAULT NULL,
  `Column122` int(11) DEFAULT NULL,
  `Column123` int(11) DEFAULT NULL,
  `Column124` int(11) DEFAULT NULL,
  `Column125` int(11) DEFAULT NULL,
  `Column126` int(11) DEFAULT NULL,
  `Column127` int(11) DEFAULT NULL,
  `Column128` int(11) DEFAULT NULL,
  `Column129` int(11) DEFAULT NULL,
  `Column130` int(11) DEFAULT NULL,
  `Column131` int(11) DEFAULT NULL,
  `Column132` int(11) DEFAULT NULL,
  `Column133` int(11) DEFAULT NULL,
  `Column134` int(11) DEFAULT NULL,
  `Column135` int(11) DEFAULT NULL,
  `Column136` int(11) DEFAULT NULL,
  `Column137` int(11) DEFAULT NULL,
  `Column138` int(11) DEFAULT NULL,
  `Column139` int(11) DEFAULT NULL,
  `Column140` int(11) DEFAULT NULL,
  `Column141` int(11) DEFAULT NULL,
  `Column142` int(11) DEFAULT NULL,
  `Column143` int(11) DEFAULT NULL,
  `Column144` int(11) DEFAULT NULL,
  `Column145` int(11) DEFAULT NULL,
  `Column146` int(11) DEFAULT NULL,
  `Column147` int(11) DEFAULT NULL,
  `Column148` int(11) DEFAULT NULL,
  `Column149` int(11) DEFAULT NULL,
  `Column150` int(11) DEFAULT NULL,
  `Column151` int(11) DEFAULT NULL,
  `Column152` int(11) DEFAULT NULL,
  `Column153` int(11) DEFAULT NULL,
  `Column154` int(11) DEFAULT NULL,
  `Column155` int(11) DEFAULT NULL,
  `Column156` int(11) DEFAULT NULL,
  `Column157` int(11) DEFAULT NULL,
  `Column158` int(11) DEFAULT NULL,
  `Column159` int(11) DEFAULT NULL,
  `Column160` int(11) DEFAULT NULL,
  `Column161` int(11) DEFAULT NULL,
  `Column162` int(11) DEFAULT NULL,
  `Column163` int(11) DEFAULT NULL,
  `Column164` int(11) DEFAULT NULL,
  `Column165` int(11) DEFAULT NULL,
  `Column166` int(11) DEFAULT NULL,
  `Column167` int(11) DEFAULT NULL,
  `Column168` int(11) DEFAULT NULL,
  `Column169` int(11) DEFAULT NULL,
  `Column170` int(11) DEFAULT NULL,
  `Column171` int(11) DEFAULT NULL,
  `Column172` int(11) DEFAULT NULL,
  `Column173` int(11) DEFAULT NULL,
  `Column174` int(11) DEFAULT NULL,
  `Column175` int(11) DEFAULT NULL,
  `Column176` int(11) DEFAULT NULL,
  `Column177` int(11) DEFAULT NULL,
  `Column178` int(11) DEFAULT NULL,
  `Column179` int(11) DEFAULT NULL,
  `Column180` int(11) DEFAULT NULL,
  `Column181` int(11) DEFAULT NULL,
  `Column182` int(11) DEFAULT NULL,
  `Column183` int(11) DEFAULT NULL,
  `Column184` int(11) DEFAULT NULL,
  `Column185` int(11) DEFAULT NULL,
  `Column186` int(11) DEFAULT NULL,
  `Column187` int(11) DEFAULT NULL,
  `Column188` int(11) DEFAULT NULL,
  `Column189` int(11) DEFAULT NULL,
  `Column190` int(11) DEFAULT NULL,
  `Column191` int(11) DEFAULT NULL,
  `Column192` int(11) DEFAULT NULL,
  `Column193` int(11) DEFAULT NULL,
  `Column194` int(11) DEFAULT NULL,
  `Column195` int(11) DEFAULT NULL,
  `Column196` int(11) DEFAULT NULL,
  `Column197` int(11) DEFAULT NULL,
  `Column198` int(11) DEFAULT NULL,
  `Column199` int(11) DEFAULT NULL,
  `Column200` int(11) DEFAULT NULL,
  `Column201` int(11) DEFAULT NULL,
  `Column202` int(11) DEFAULT NULL,
  `Column203` int(11) DEFAULT NULL,
  `Column204` int(11) DEFAULT NULL,
  `Column205` int(11) DEFAULT NULL,
  `Column206` int(11) DEFAULT NULL,
  `Column207` int(11) DEFAULT NULL,
  `Column208` int(11) DEFAULT NULL,
  `Column209` int(11) DEFAULT NULL,
  `Column210` int(11) DEFAULT NULL,
  `Column211` int(11) DEFAULT NULL,
  `Column212` int(11) DEFAULT NULL,
  `Column213` int(11) DEFAULT NULL,
  `Column214` int(11) DEFAULT NULL,
  `Column215` int(11) DEFAULT NULL,
  `Column216` int(11) DEFAULT NULL,
  `Column217` int(11) DEFAULT NULL,
  `Column218` int(11) DEFAULT NULL,
  `Column219` int(11) DEFAULT NULL,
  `Column220` int(11) DEFAULT NULL,
  `Column221` int(11) DEFAULT NULL,
  `Column222` int(11) DEFAULT NULL,
  `Column223` int(11) DEFAULT NULL,
  `Column224` int(11) DEFAULT NULL,
  `Column225` int(11) DEFAULT NULL,
  `Column226` int(11) DEFAULT NULL,
  `Column227` int(11) DEFAULT NULL,
  `Column228` int(11) DEFAULT NULL,
  `Column229` int(11) DEFAULT NULL,
  `Column230` int(11) DEFAULT NULL,
  `Column231` int(11) DEFAULT NULL,
  `Column232` int(11) DEFAULT NULL,
  `Column233` int(11) DEFAULT NULL,
  `Column234` int(11) DEFAULT NULL,
  `Column235` int(11) DEFAULT NULL,
  `Column236` int(11) DEFAULT NULL,
  `Column237` int(11) DEFAULT NULL,
  `Column238` int(11) DEFAULT NULL,
  `Column239` int(11) DEFAULT NULL,
  `Column240` int(11) DEFAULT NULL,
  `Column241` int(11) DEFAULT NULL,
  `Column242` int(11) DEFAULT NULL,
  `Column243` int(11) DEFAULT NULL,
  `Column244` int(11) DEFAULT NULL,
  `Column245` int(11) DEFAULT NULL,
  `Column246` int(11) DEFAULT NULL,
  `Column247` int(11) DEFAULT NULL,
  `Column248` int(11) DEFAULT NULL,
  `Column249` int(11) DEFAULT NULL,
  `Column250` int(11) DEFAULT NULL,
  `Column251` int(11) DEFAULT NULL,
  `Column252` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `many_records`
--

DROP TABLE IF EXISTS `many_records`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `many_records` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `type` smallint(5) unsigned NOT NULL,
  `zone_id` int(10) unsigned NOT NULL,
  `player_id` smallint(5) unsigned DEFAULT NULL,
  `map_id` tinyint(3) unsigned NOT NULL,
  `text_field` text DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=41011 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping routines for database 'Godot_Test'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-03-24  5:42:05
