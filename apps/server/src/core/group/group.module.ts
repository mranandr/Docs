import { Module } from '@nestjs/common';
import { GroupService } from './services/group.service';
import { GroupController } from './group.controller';
import { GroupUserService } from './services/group-user.service';
import { DatabaseModule } from '@docmost/db/database.module';
@Module({
  imports: [DatabaseModule], 
  controllers: [GroupController],
  providers: [GroupService, GroupUserService],
  exports: [GroupService, GroupUserService],
})
export class GroupModule {}
