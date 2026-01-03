import {
  MessageBody,
  OnGatewayConnection,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { KeycloakTokenService } from 'src/core/auth/token.service'; 
import { OnModuleDestroy } from '@nestjs/common';
import { SpaceMemberRepo } from '@docmost/db/repos/space/space-member.repo';
import * as cookie from 'cookie';
import { UserService } from 'src/core/user/user.service';
import { JwtType } from 'src/core/auth/auth.util';

@WebSocketGateway({
  cors: { origin: '*' },
  transports: ['websocket'],
})
export class WsGateway implements OnGatewayConnection, OnModuleDestroy {
  @WebSocketServer()
  server: Server;
  constructor(
      private readonly keycloakTokenService: KeycloakTokenService,
      private spaceMemberRepo: SpaceMemberRepo,
      private readonly userService: UserService,

  ) {}

async handleConnection(client: Socket): Promise<void> {
  try {
    const cookies = cookie.parse(client.handshake.headers.cookie || '');
    const token = cookies['authToken'];

    if (!token) {
      client.emit('Unauthorized');
      client.disconnect();
      return;
    }

    const decoded = await this.keycloakTokenService.verifyToken(
      token,
      JwtType.ACCESS,  
    );

    const email = decoded.email;
    const user = await this.userService.findByEmail(email);

    if (!user) {
      client.emit('Unauthorized');
      client.disconnect();
      return;
    }

    const workspaceId = user.workspaceId;
    const userId = user.id;

    const spaceIds = await this.spaceMemberRepo.getUserSpaceIds(userId);

    client.join(`workspace-${workspaceId}`);
    spaceIds.forEach((id) => client.join(`space-${id}`));

    console.log(`User ${email} connected to websocket`);
  } catch (err) {
    client.emit('Unauthorized');
    client.disconnect();
  }
}



  @SubscribeMessage('message')
  handleMessage(client: Socket, data: any): void {
    const spaceEvents = [
      'updateOne',
      'addTreeNode',
      'moveTreeNode',
      'deleteTreeNode',
    ];

    if (spaceEvents.includes(data?.operation) && data?.spaceId) {
      const room = this.getSpaceRoomName(data.spaceId);
      client.broadcast.to(room).emit('message', data);
      return;
    }

    client.broadcast.emit('message', data);
  }

  @SubscribeMessage('join-room')
  handleJoinRoom(client: Socket, @MessageBody() roomName: string): void {
    // if room is a space, check if user has permissions
    //client.join(roomName);
  }

  @SubscribeMessage('leave-room')
  handleLeaveRoom(client: Socket, @MessageBody() roomName: string): void {
    client.leave(roomName);
  }

  onModuleDestroy() {
    if (this.server) {
      this.server.close();
    }
  }

  getSpaceRoomName(spaceId: string): string {
    return `space-${spaceId}`;
  }
}
